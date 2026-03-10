# AdmissionVet Roadmap

スキャン結果から「検出」を「防止」にシフトするツール。
ManifestVet/RBACVet/NetworkVet 等の違反パターンを OPA/Gatekeeper・Kyverno ポリシーとして自動生成し、
Kubernetes Admission Webhook として適用することでリアルタイムブロックを実現する。

---

## v0.1.0 — OPA/Gatekeeper ポリシー生成 (Week 1–2)

**Goal:** 既存のスキャン違反から OPA/Gatekeeper の ConstraintTemplate を自動生成する。

### ConstraintTemplate 生成
- [x] ManifestVet 違反 → ConstraintTemplate (Rego) への変換
  - MV1001: privileged コンテナ禁止
  - MV1002: hostPID/hostIPC/hostNetwork 禁止
  - MV1003: hostPath マウント禁止・制限
  - MV1007: readOnlyRootFilesystem 強制
  - MV2001: env への Secret 直書き禁止
- [x] RBACVet 違反 → ClusterRole/Role の制約生成
  - wildcard verb/resource 禁止ポリシー (RB1001/RB1002)
  - system:masters 以外への cluster-admin 付与禁止 (RB1003)
- [x] NetworkVet 違反 → NetworkPolicy テンプレート生成
  - default-deny NetworkPolicy の自動生成 (NV1001)
  - namespace ラベルベースの許可ルール

### 生成オプション
- [x] `admissionvet generate --from manifestvet-results.json --engine gatekeeper`
- [ ] K8sVet の統合スキャン結果から直接生成
- [x] `--severity error` でエラーのみポリシー化
- [x] `--namespace` で対象 namespace を限定

### 出力フォーマット
- [x] YAML (kubectl apply 可能)
- [x] Helm chart
- [x] Kustomize overlay

---

## v0.2.0 — Kyverno ポリシー生成 (Week 3–4)

**Goal:** Kyverno の ClusterPolicy/Policy を自動生成する。

### Policy 生成
- [x] `validate` ルール: マニフェスト検証 (ManifestVet 相当)
- [x] `mutate` ルール: デフォルト値の自動補完
  - `readOnlyRootFilesystem: true` を未設定コンテナに自動付与 (MV1007-MUTATE)
  - `automountServiceAccountToken: false` の自動設定 (MV-MUTATE-AUTOMOUNT)
  - `imagePullPolicy: Always` の強制 (MV-MUTATE-IMAGEPULL)
- [x] `generate` ルール: namespace 作成時に NetworkPolicy を自動生成 (NV1001)
- [x] `verify-images` ルール: Cosign 署名検証ポリシー生成 (IV1001)

### 差分モード
- [x] 既存ポリシーとの差分確認 (`--diff`)
- [ ] ドライラン評価 (`kyverno apply --dry-run`)
- [ ] 既存クラスターリソースへの影響シミュレーション

---

## v0.3.0 — Webhook バリデーション (Week 5–6)

**Goal:** 設定した Admission Webhook の動作を検証・テストする。

### 既存 Webhook の検証
- [x] ValidatingWebhookConfiguration の設定ミス検出
  - `failurePolicy: Ignore` による回避リスク検出 (AV3001)
  - `namespaceSelector` の穴検出 (kube-system 除外漏れ等) (AV3003)
  - `timeoutSeconds` が短すぎる場合の警告 (フォールバック動作) (AV3002)
  - TLS 証明書の有効期限チェック (AV3005)
- [x] MutatingWebhookConfiguration の設定ミス検出
  - `reinvocationPolicy` の設定確認 (AV4001)
  - ループリスク検出 (Mutate した結果が再度 Mutate をトリガー)

### Webhook の到達性テスト
- [x] `admissionvet webhook test --from webhook.yaml` で TLS 到達性確認・応答時間測定
- [x] 各 Webhook の応答時間測定
- [x] 証明書チェーンの検証 (AV3006: 自己署名検出・チェーン整合性検証)

---

## v0.4.0 — Pod Security Admission (PSA) 検証 (Week 7)

**Goal:** PodSecurity Admission の設定と実態のギャップを検出する。

- [ ] namespace の PSA ラベル (`pod-security.kubernetes.io/enforce` 等) の確認
- [ ] ラベルなし namespace の検出と推奨レベルの提案
- [x] 既存ワークロードが PSA レベルに準拠しているか事前チェック
  - `baseline` / `restricted` 各レベルでのシミュレーション (PSA-BASE-*, PSA-REST-*)
- [x] PSA 違反になるワークロードの事前洗い出し (移行計画支援)
- [x] `admissionvet psa simulate --level restricted --namespace team-1` コマンド

---

## v0.5.0 — ポリシーライブラリ (Week 8–9)

**Goal:** 即使えるポリシーテンプレートライブラリを提供する。

### ビルトインポリシーセット
- [x] `baseline`: CIS Benchmark 相当のベーシックセキュリティ
- [x] `restricted`: 最小権限・最大制限
- [x] `gke-standard`: GKE 推奨設定セット
- [x] `eks-standard`: EKS 推奨設定セット
- [x] `pci-dss`: PCI-DSS 準拠ポリシーセット

### ポリシー管理
- [x] `admissionvet list-policies` で利用可能ポリシー一覧
- [x] `admissionvet apply --preset gke-standard` でまとめて適用
- [x] ポリシーのバージョン管理・ロールバック (`admissionvet version list/rollback`)
- [x] 組織カスタムポリシーのレジストリ登録 (`admissionvet registry add/list/remove`)

---

## v0.6.0 — ライブクラスタードライラン (Week 10)

**Goal:** ポリシー適用前に既存リソースへの影響を全件シミュレーションする。

- [x] `admissionvet dryrun --manifest manifests/ --policy output/` でファイルベースのポリシー評価
- [x] 影響リソースの一覧出力 (namespace / リソース種別 / 件数)
- [x] ブロックされる Deployment のロールアウト影響シミュレーション (replicas 数・ポリシー名を表示)
- [x] 段階適用計画の自動生成 (`warn` → `enforce` の移行スケジュール)

---

## K8sVet 取り込み計画

| バージョン | K8sVet対応 | 内容 |
|---|---|---|
| AdmissionVet v0.1.0 完了後 | K8sVet v0.6.0 | `k8svet scan . --emit-policies` で OPA/Kyverno ポリシー出力 ✅ (K8sVet出力フォーマット対応済) |
| AdmissionVet v0.3.0 完了後 | K8sVet v0.6.0 | `k8svet scan --cluster` に Webhook 設定検証を追加 ✅ |
| AdmissionVet v0.4.0 完了後 | K8sVet v0.6.0 | `k8svet scan --cluster` に PSA ギャップ分析を追加 ✅ |
| AdmissionVet v0.5.0 完了後 | K8sVet v0.7.0 | `k8svet harden --preset gke-standard` コマンド追加 ✅ |

```bash
# K8sVet統合後のイメージ

# スキャン結果から直接ポリシー生成
k8svet scan . --emit-policies kyverno --output policies/
# → policies/deny-privileged.yaml
# → policies/require-resource-limits.yaml
# → policies/default-deny-netpol.yaml

# クラスターの Webhook 設定検証
k8svet scan --cluster
# → [AdmissionVet]  cluster://  3 warnings (failurePolicy: Ignore x2, cert expires in 7d)

# ポリシー適用前のドライラン
k8svet harden --dryrun --preset gke-standard
# → Simulating 24 policies against 1,847 resources...
# → Would block: 312 resources across 28 namespaces
```

### 違反→ポリシーの自動連携フロー
```
k8svet scan .
  ↓ (ManifestVet: 361 errors)
k8svet scan . --emit-policies kyverno
  ↓ (361件の違反 → Kyverno ClusterPolicy に変換)
kubectl apply -f policies/
  ↓ (以降の違反するデプロイを自動ブロック)
```

---

## ルールID体系

```
AV1xxx  OPA/Gatekeeper ポリシー検証
AV2xxx  Kyverno ポリシー検証
AV3xxx  ValidatingWebhookConfiguration 設定ミス
AV4xxx  MutatingWebhookConfiguration 設定ミス
AV5xxx  Pod Security Admission 設定
AV6xxx  ポリシーライブラリ関連
```
