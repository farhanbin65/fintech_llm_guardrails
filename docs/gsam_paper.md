Title: Securing LLM-Powered Intelligent Systems: A Deployable Middleware Architecture for Prompt Injection Defence and Data Privacy
Author: Farhan Bin Hossain
Institution: Ulster University London
Programme: BSc Computing Systems (Final Year)

Abstract
The deployment of Large Language Models (LLMs) as decision-support components within intelligent systems — including AI-assisted process monitoring, automated reporting tools, and human-machine dialogue interfaces — introduces two classes of security risk that existing guardrail frameworks address in isolation. First, sensitive operational data transmitted verbatim to third-party LLM APIs may be logged, retained for model training, or exposed through provider-side data breaches, raising significant data governance concerns. Second, prompt injection attacks — in which adversarial instructions are embedded within user inputs or imported data — may hijack LLM behaviour, cause unauthorised action execution, or exfiltrate system context. Existing tools such as LLM Guard and Microsoft Presidio address either privacy or injection defence independently; no deployable, integrated middleware solution combining both has been evaluated empirically in the literature.
This paper presents a novel eight-layer middleware pipeline interposed between an intelligent application and its LLM API. The pipeline incorporates a context provenance tracker, a continuous risk-scoring engine, a PII redaction and re-mapping layer, a cryptographic canary token system for context leakage detection, and a declarative action allowlist enforcing the principle that the LLM may propose but the middleware decides. Implemented as a proof-of-concept in Python and evaluated against 107 curated attack cases and 270 adaptive mutation variants, the system achieves a 100% block rate on direct instruction override attacks at 5.8ms mean latency — a 51× latency improvement over LLM Guard — whilst maintaining semantic preservation scores of ROUGE-1 0.986 and BERTScore F1 0.772. These results suggest that lightweight, rule-augmented middleware represents a viable and performant approach to trustworthy LLM integration in intelligent systems.
Keywords: large language models; prompt injection; data privacy; middleware architecture; intelligent systems; Industry 4.0; trustworthy AI; cyber-physical systems

1. Introduction
Intelligent systems across manufacturing, logistics, and operational domains increasingly incorporate LLM-based components for natural language interaction, anomaly reporting, and decision support [DAS, 2024]. However, the integration of external LLM APIs into these pipelines creates a trust boundary at which sensitive operational data — process parameters, personnel records, proprietary configurations — is transmitted to third-party infrastructure outside the organisation's direct control. Concurrently, prompt injection — a class of adversarial attack in which malicious instructions are embedded within legitimate inputs — has emerged as a critical vulnerability in LLM-integrated systems [GRESHAKE, 2023], capable of bypassing safety constraints and causing unintended autonomous actions.
Existing mitigation tools operate on a single axis: Microsoft Presidio [MICROSOFT, 2019] detects personally identifiable information (PII) in text but provides no injection defence; LLM Guard [PROTECT AI, 2023] performs injection classification but introduces latency overhead exceeding 300ms per request, rendering it unsuitable for real-time intelligent system pipelines. No published work evaluates a combined, deployable middleware addressing both threat classes simultaneously within a single architecture.
This paper makes the following contributions: (1) a novel eight-layer middleware architecture integrating PII redaction, provenance tracking, risk scoring, canary token leakage detection, and declarative action control; (2) an adaptive red-team evaluation methodology generating 270 mutation variants across five attack strategies; and (3) empirical evidence that a lightweight rule-augmented approach achieves superior detection rates and 51× lower latency compared to existing neural classifier-based alternatives.
2. Aim & Objectives
Aim: To design, implement, and empirically evaluate a deployable middleware pipeline that protects LLM-integrated intelligent systems from prompt injection attacks and sensitive data leakage, without requiring modification to the underlying LLM or the host application.
Objectives:

Design an eight-layer middleware architecture addressing both PII leakage and prompt injection as a unified pipeline
Implement five novel middleware components in Python including provenance tracking, risk scoring, canary token injection, and declarative action allowlisting
Evaluate detection performance against a 107-case static corpus spanning eight injection vector categories
Evaluate robustness under adaptive mutation — 270 variants generated via five mutation strategies
Benchmark latency and semantic preservation against LLM Guard and Microsoft Presidio
Demonstrate applicability to any LLM-integrated intelligent system, not limited to a single domain


3. Methodology
The middleware pipeline was implemented in Python 3.11 as a modular, provider-agnostic layer requiring no modification to the host application or LLM API. The eight layers operate sequentially on each request-response cycle as follows.
Input processing (Layers 0–2): A provenance tracker labels each segment of the prompt context by origin — system instructions, user input, or imported external data — enabling differential trust assignment and indirect injection detection in data imported from external sources [GRESHAKE, 2023]. A risk scorer computes a composite threat score across five weighted dimensions: injection signal strength, PII density, provenance anomaly, action request frequency, and canary proximity. An input sanitiser applies pattern-matched rules against a curated taxonomy of injection signals.
PII redaction (Layer 3): Named entity recognition identifies PII tokens — names, account identifiers, financial figures, contact details — which are replaced with typed pseudonyms (e.g. [PERSON_1], [ACCOUNT_2]) prior to transmission. A re-mapping registry restores original values in the returned response, preserving conversational coherence whilst ensuring no PII crosses the third-party API boundary.
Canary system (Layer 3b): Cryptographically unique canary tokens are injected into the system prompt. Their presence in the LLM response is monitored as an indicator of prompt extraction or context leakage [BOWEN, 2009].
Output control (Layers 4a–4b): An output validator scans LLM responses for residual PII leakage. A declarative action allowlist governs tool call authorisation — the LLM may propose actions, but execution requires explicit allowlist approval across three risk tiers, aligned with OWASP LLM Top 10 recommendations [OWASP, 2024].
Evaluation methodology: A static corpus of 107 cases spanning eight injection vector categories was constructed using the deepset/prompt-injections dataset [DEEPSET, 2024] augmented with domain-specific cases. An adaptive red-team evaluator applied five mutation strategies — character substitution, instruction fragmentation, language switching, role-play wrapping, and semantic paraphrase — generating 270 mutation variants to assess robustness beyond static benchmarks. Semantic preservation was measured via ROUGE [LIN, 2004] and BERTScore against unredacted baseline responses.

4. Results
Table 1. Static corpus detection performance (107 cases).
SystemBlock RateFPRMean LatencyOurs (8-layer middleware)100%0.0%5.8msLLM Guard68.5%0.0%300.3msPromptGuard 86M68.3%80.4%291.2msPresidioPII onlyN/AN/A
Table 2. Adaptive red-team results (377 cases, 5 mutation strategies).
Attack VectorOriginal+MutationsBenign FPRDirect Override (V1)100%90.6%0.0%Obfuscated Injection (V6)88.9%85.2%0.0%False Context (V8)90.0%78.3%0.0%Action Hijacking (V4)10.0%8.3%0.0%PII Exfiltration (V5)0.0%0.0%0.0%Overall63.0%57.1%11.3%
Semantic preservation: ROUGE-1 0.986, ROUGE-2 0.967, BERTScore F1 0.772.

5. Discussion
Results indicate that the proposed middleware achieves superior detection performance and substantially lower latency compared to existing neural classifier-based alternatives on the static corpus. The 51× latency advantage over LLM Guard suggests that rule-augmented architectures may be more appropriate than neural classifiers for latency-sensitive intelligent system pipelines.
Adaptive red-team evaluation reveals limitations in semantic attack detection: action hijacking (V4, 8.3%) and PII exfiltration via indirect inference (V5, 0.0%) remain underdetected. These vectors rely on contextual reasoning rather than explicit injection signals, suggesting that pure pattern-matching approaches are insufficient for adversarially sophisticated attacks. An 11.3% false positive rate under mutation conditions indicates scope for threshold calibration. Future work will investigate LLM-based semantic analysis as a complementary detection layer.
The middleware's provider-agnostic, modular design indicates applicability beyond the proof-of-concept domain — any intelligent system pipeline transmitting sensitive operational data to an external LLM API may benefit from analogous protection.

6. Conclusion
This paper presents and empirically evaluates an eight-layer middleware architecture for protecting LLM-integrated intelligent systems from prompt injection and data leakage. Achieving 100% detection of direct override attacks at 5.8ms latency with zero false positives, and maintaining ROUGE-1 semantic preservation of 0.986, the system demonstrates that lightweight middleware represents a viable alternative to computationally expensive neural guardrail classifiers. Limitations in semantic attack detection identify clear directions for future research. The implementation is open-source and designed for straightforward integration into existing intelligent system architectures.

References

European Parliament. General Data Protection Regulation, Article 5(1)(c). Official Journal of the European Union, 2018.
Liu, Y. et al. Automatic and Universal Prompt Injection Attacks against Large Language Models. arXiv:2403.04957, 2024.
Wong, R. Prompt Injection Attacks on Large Language Models: A Survey. CMC, vol. 87, 2026.
Carlini, N. et al. Extracting Training Data from Large Language Models. USENIX Security, 2021.
Das, R. et al. Security and Privacy Challenges of Large Language Models: A Survey. arXiv:2402.00888, 2024.
Greshake, K. et al. Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection. AISec, 2023.
Protect AI. LLM Guard — The Security Toolkit for LLM Interactions. GitHub, 2023.
Microsoft. Presidio — Data Protection and De-identification SDK. GitHub, 2019.
Lin, C.-Y. ROUGE: A Package for Automatic Evaluation of Summaries. ACL, 2004.
OWASP. OWASP Top 10 for Large Language Model Applications. OWASP Foundation, 2024.
Deepset. prompt-injections dataset. HuggingFace, 2024.
Bowen, B. et al. Baiting Inside Attackers Using Deceit and Trap-Based Defences. SecureComm, 2009.