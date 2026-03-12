# AdmissionVet Roadmap

スキャン結果から「検出」を「防止」にシフトするツール。
ManifestVet/RBACVet/NetworkVet/Trivy 等の違反パターンを OPA/Gatekeeper・Kyverno ポリシーとして自動生成し、
Kubernetes Admission Webhook として適用することでリアルタイムブロックを実現する。

---

## 完了済み

### v0.1.0 — OPA/Gatekeeper ポリシー生成
- [x] MV1001–MV2001, RB1001–RB1003, NV1001 ConstraintTemplate/Constraint 生成
- [x] `--severity` / `--namespace` / `--output` / `--format` (yaml/helm/kustomize) フラグ
- [x] `--diff` モード（既存ファイルとの行差分比較）

### v0.2.0 — Kyverno ポリシー生成
- [x] validate / mutate / generate / verify-images ルール生成
- [x] MV1007-MUTATE, MV-MUTATE-AUTOMOUNT, MV-MUTATE-IMAGEPULL, IV1001
- [x] `--diff` モード対応

### v0.3.0 — Webhook バリデーション
- [x] AV3001–AV3006 (failurePolicy, timeout, namespace exclusion, TLS cert expiry, cert chain)
- [x] AV4001 (reinvocationPolicy)
- [x] `admissionvet webhook test` TLS 到達性確認・応答時間測定

### v0.4.0 — Pod Security Admission シミュレーション
- [x] `admissionvet psa simulate --level baseline/restricted`
- [x] 既存ワークロードの PSA 準拠確認・移行計画支援

### v0.5.0 — ポリシーライブラリ
- [x] 5 プリセット (baseline, restricted, gke-standard, eks-standard, pci-dss)
- [x] `admissionvet list-policies` / `apply --preset`
- [x] `admissionvet version list/rollback`（最新 5 世代）
- [x] `admissionvet registry add/list/remove`（~/.admissionvet/registry/）

### v0.6.0 — ドライラン・ライブ監査
- [x] `admissionvet dryrun` — ポリシーをマニフェストにシミュレーション適用
- [x] ロールアウト影響分析（Deployment/StatefulSet replicas 数・ブロックポリシー名）
- [x] `admissionvet audit` — ライブクラスター全リソースのセキュリティ監査
- [x] `admissionvet drift` — ローカルポリシーとクラスター状態の差分検出

### 精度改善・テスト整備（継続）
- [x] Trivy k8s JSON 入力対応（KSV → AdmissionVet ルール ID 自動変換）
- [x] K8sVet 統合フォーマット自動検出
- [x] `--exceptions` 対応（generate / dryrun / audit 全コマンド）
- [x] Gatekeeper MV1001 Rego: `object.get()` で nil-safe に
- [x] Gatekeeper MV1002: ワークロード Kind のみに限定
- [x] dryrun RBAC チェック: top-level `rules`/`roleRef`/`subjects` フィールド対応
- [x] NV1001 default-deny 検出: `ingress: []`（明示的空スライス）を正しく扱う
- [x] Kyverno MV2001: `AnyIn` グロブ → `Regex` オペレーターに修正
- [x] Kyverno MV1003/RB1003: `value: "0"` → `value: 0`（数値型）に修正
- [x] exceptions.Matches(): 大文字小文字区別なしに変更
- [x] YAML 分割: `---` 先頭ドキュメントの消失を修正
- [x] Replicas 文字列型パース対応（`"3"` → `int`）
- [x] kyverno/rbacvet テスト追加（RB1001–RB1003）
- [x] kyverno/networkvet テスト追加（NV1001）

### v0.7.0 — 新規ルール（検出カバレッジ拡充）
- [x] **MV1004**: root ユーザー実行禁止（`runAsUser: 0` / `runAsNonRoot: false`）
- [x] **MV1005**: 危険 Linux Capability 禁止（ALL, SYS_ADMIN, NET_ADMIN 等 15 種）
- [x] **MV1006**: `allowPrivilegeEscalation: false` 未設定の検出
- [x] 各ルールの Gatekeeper Rego 実装（`object.get()` で nil-safe）
- [x] 各ルールの Kyverno ClusterPolicy 実装
- [x] audit/checks.go に check 関数追加・workloadChecks 登録
- [x] 単体テスト追加（audit: 14 件, gatekeeper: 9 件, kyverno: 9 件）
- [x] Trivy KSV マップに MV1004–MV1006 対応 KSV を追加

---

## 次のフェーズ

### v0.8.0 — CI/CD ファーストクラスサポート

**`admissionvet scan` コマンド**（スキャンツール非依存化）
- manifest ファイルを直接渡してスキャン結果なしで完結
- 内部で dryrun の check 関数群を流用
- `admissionvet scan --manifest k8s/ --engine kyverno --output output/`

**SARIF 出力**（GitHub Code Scanning 統合）
- `--output-format sarif` で GitHub Actions の `upload-sarif` に対応
- Security タブへのインライン表示

**JUnit XML 出力**（CI レポート統合）
- `--output-format junit` で Jenkins / CircleCI / GitHub Actions test reporter 対応

**GitHub Actions アクション**
- `AdmissionVet/admissionvet-action@v1` として公開

---

### v0.9.0 — 診断品質向上

**`admissionvet fix` コマンド**（ローカル自動修正）
- MV1001/MV1006/MV1007 相当の修正を manifest ファイルに直接適用
- `--dry-run` フラグで差分確認のみ

**コンプライアンススコア**
- ルール別重み付けスコアリング（0–100%）
- CIS Benchmark / NSA / PCI-DSS フレームワーク別スコア

**修正ガイド付き出力**
- 各違反に対して修正 YAML スニペットと参照リンクを表示

---

### v1.0.0 — マルチクラスター対応・ポリシーライフサイクル完結

**マルチクラスター audit**
- `--context prod,staging` で複数クラスター同時監査・差分比較

**ポリシーベースライン管理**
- `admissionvet baseline create/diff` でスナップショット差分を追跡
- 新規違反のみ通知するモード

**カスタムルールの Rego/CEL 対応**
- registry YAML に `rego:` フィールドでインラインポリシーを記述可能に

**Webhook サーバーモード**
- `admissionvet serve --port 8443` で admissionvet 自体が ValidatingWebhook として動作
- Gatekeeper/Kyverno なしの軽量構成に対応

---

## ルール ID 体系

```
MV1xxx  ManifestVet — Pod/コンテナセキュリティ
MV2xxx  ManifestVet — データセキュリティ（env secrets 等）
RB1xxx  RBACVet — RBAC ロール・バインディング
NV1xxx  NetworkVet — ネットワークポリシー
IV1xxx  ImagePolicy — イメージ検証（Kyverno 専用）
AV3xxx  ValidatingWebhookConfiguration 設定ミス
AV4xxx  MutatingWebhookConfiguration 設定ミス
CUSTOM-xxx  ユーザー定義ルール（registry 経由）
```
