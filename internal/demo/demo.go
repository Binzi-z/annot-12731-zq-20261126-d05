// Package demo orchestrates the canonical worked example: it synthesizes the
// three sealed copies, writes per-watermark reports and the minimal conflict
// certificate + trust bundle, then verifies the certificate from disk exactly
// as an offline third party would.
package demo

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"reviewer12731/internal/model"
	"reviewer12731/internal/reconcile"
	"reviewer12731/internal/segment"
	"reviewer12731/internal/stable"
	"reviewer12731/internal/synth"
)

// Run executes the demo, writing artifacts to outDir and human output to out.
func Run(outDir string, out io.Writer) error {
	w, err := synth.NewCanonicalWorld()
	if err != nil {
		return err
	}

	fmt.Fprintln(out, "==============================================================")
	fmt.Fprintln(out, " 离线复核器 12731 · 三份已封存副本合成场景")
	fmt.Fprintln(out, "==============================================================")
	fmt.Fprintf(out, "受信起点: partition=%s seq=%d digest=%s\n",
		w.Anchor.Partition, w.Anchor.Seq, short(w.Anchor.Digest))
	fmt.Fprint(out, "副本: ")
	for i, c := range w.Copies {
		if i > 0 {
			fmt.Fprint(out, " | ")
		}
		fmt.Fprintf(out, "%s(%s, 边界%d, 缺段%v)", c.Name, c.Location, len(c.Boundaries), c.Missing)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "历史恢复水位结论（每个哈希可重复构建）:")
	fmt.Fprintf(out, "  %-8s %-26s %-8s %-16s %s\n", "水位", "状态", "可信到", "最早冲突", "结论哈希")
	for _, wm := range synth.Watermarks {
		r := w.Reviewer.Review(wm)
		cs := "-"
		if r.EarliestConflict != nil {
			cs = fmt.Sprintf("seq%d/%s", r.EarliestConflict.Seq, r.EarliestConflict.Kind)
		}
		fmt.Fprintf(out, "  %-8d %-26s %-8d %-16s %s\n",
			wm, r.Status, r.TrustedThroughSeq, cs, short(r.ConclusionHash))
		if err := writeJSON(filepath.Join(outDir, fmt.Sprintf("report-wm%02d.json", wm)), r); err != nil {
			return err
		}
	}
	fmt.Fprintln(out)

	r7 := w.Reviewer.Review(7)
	fmt.Fprintf(out, "指定水位 7: 最长可信前缀连接数=%d (可信到 seq %d)\n",
		r7.ConnectedCount, r7.TrustedThroughSeq)
	fmt.Fprintf(out, "  未证区间(紧邻前缀): %+v\n", r7.BlockingInterval)
	fmt.Fprintf(out, "  全部未证区间: %v\n", r7.UnprovenIntervals)
	if c := r7.EarliestConflict; c != nil {
		fmt.Fprintf(out, "  最早已证冲突: seq %d 类型=%s\n", c.Seq, c.Kind)
		fmt.Fprintf(out, "    边界A %s prev=%s\n", short(c.A.ID()), short(c.PrevA))
		fmt.Fprintf(out, "    边界B %s prev=%s\n", short(c.B.ID()), short(c.PrevB))
	}
	fmt.Fprintf(out, "  有效交接: %v  已撤销交接: %v\n", r7.EffectiveHandoffs, r7.RevokedHandoffs)
	for _, rj := range r7.RejectedRevocations {
		fmt.Fprintf(out, "  已拒绝撤销: %s -> %s (%s)\n", rj.RevocationID, rj.TargetID, rj.Reason)
	}
	fmt.Fprintln(out)

	cert, err := reconcile.BuildSealedConflictCert(r7, w.Source)
	if err != nil {
		return err
	}
	certPath := filepath.Join(outDir, "conflict-cert-wm7.json")
	trustPath := filepath.Join(outDir, "trust-bundle.json")
	if err := writeJSON(certPath, cert); err != nil {
		return err
	}
	bundle := w.Ring.Bundle(w.Anchor)
	if err := writeJSON(trustPath, bundle); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outDir, "sealed-copies.json"), w.Copies); err != nil {
		return err
	}
	fmt.Fprintf(out, "最小边界证书已写出: %s\n", certPath)
	fmt.Fprintf(out, "常量信任束已写出:   %s (第三方只需它+证书，无需原库)\n", trustPath)
	fmt.Fprintf(out, "三份副本已写出:     %s\n", filepath.Join(outDir, "sealed-copies.json"))

	fmt.Fprintln(out)
	fmt.Fprintln(out, "第三方离线验证（仅读取证书与信任束两个小文件）:")
	if err := VerifyCertFiles(certPath, trustPath, out); err != nil {
		return err
	}

	fmt.Fprintln(out)
	if err := Large(out); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n完成。所有产物位于 %s\n", outDir)
	return nil
}

// VerifyCertFiles reloads a certificate (and optional trust bundle) from disk
// and runs the standalone verifier, printing the verdict.
func VerifyCertFiles(certPath, trustPath string, out io.Writer) error {
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	var cert reconcile.ConflictCert
	if err := json.Unmarshal(certRaw, &cert); err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	var ring model.KeyRing
	if trustPath != "" {
		trustRaw, err := os.ReadFile(trustPath)
		if err != nil {
			return err
		}
		var tb model.TrustBundleJSON
		if err := json.Unmarshal(trustRaw, &tb); err != nil {
			return fmt.Errorf("parse trust bundle: %w", err)
		}
		ring, err = model.LoadTrustBundle(tb)
		if err != nil {
			return err
		}
	}
	v, err := reconcile.VerifyConflictCert(&cert, ring)
	b, _ := stable.JSON(v)
	fmt.Fprintln(out, string(b))
	if err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}
	fmt.Fprintln(out, ">> 已检出互相矛盾的两个边界（同一序号、不同前序摘要）")
	return nil
}

// Large builds the big fixture and prints measured localized/global comparisons.
func Large(out io.Writer) error {
	fx, err := synth.NewDefaultLarge()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "大数据三空档局部扫描度量:")
	fmt.Fprintf(out, "  规模: %d 分区 × %d 段 × %d 边界 = %d 条; 移除3个隔开的段形成空档\n",
		fx.Partitions, fx.BlocksPer, fx.ItemsPerBlock,
		fx.Partitions*fx.BlocksPer*fx.ItemsPerBlock)
	for i, gf := range fx.Fills {
		fx.Meter.Reset()
		if _, err := fx.Store.VerifyFill(gf.GapLo, gf.GapHi, gf.Segment); err != nil {
			return err
		}
		global := fx.Store.NaiveGlobalScanComparisons(segment.Key{
			Partition: gf.Partition, Seq: gf.GapLo,
		})
		fmt.Fprintf(out, "  空档%d %s [%d..%d]: %s | 全局裸扫比较≈%d | 局部/全局=%.4f\n",
			i, gf.Partition, gf.GapLo, gf.GapHi, fx.Meter.Report(),
			global, float64(fx.Meter.TotalComparisons())/float64(global))
	}
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := stable.JSON(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func short(d model.Digest) string {
	s := string(d)
	if len(s) > 22 {
		return s[:14] + "..." + s[len(s)-8:]
	}
	return s
}
