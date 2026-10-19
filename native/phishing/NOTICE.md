# PhishLang model attribution and development provenance

This local development build includes a Core ML conversion of the PhishLang
MobileBERT checkpoint from UTA-SPRLab/phishlang, commit
`6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd`.

Authors: Sayak Saha Roy and Shirin Nilizadeh, University of Texas at Arlington.
Paper: *PhishLang: A Real-Time, Fully Client-Side Phishing Detection Framework
Using MobileBERT*, https://arxiv.org/abs/2408.05667.
Repository: https://github.com/UTA-SPRLab/phishlang.

The publication is licensed under Creative Commons Attribution 4.0:
https://creativecommons.org/licenses/by/4.0/.
The reviewed repository does not specify a separate license grant for its code,
fine-tuned weights or processed training data. This notice records that scope
uncertainty; it does not assign the paper license to those separate artifacts or
relicense them under Kumo's MIT license. Commercial redistribution rights have
not been established by this local port.

The underlying Google MobileBERT checkpoint declares Apache License 2.0:
https://huggingface.co/google/mobilebert-uncased. The corresponding license text
is included as LICENSE-MobileBERT.txt. This upstream license does not establish
the rights to PhishLang-specific additions.

Kumo changes the runtime to native Swift/Core ML CPU inference; uses a bounded,
privacy-filtered representation of page content; and caps token windows and
rescans. Form values, editable content and script bodies are omitted. These
changes mean the authors' reported detection metrics do not describe this port.
No endorsement by the authors, Google or Apple is implied.

The original Kumo integration and tokenizer implementation retain Kumo's MIT
license. Apple Core ML is a system framework. Python, PyTorch, Transformers and
Core ML Tools are conversion-time dependencies and are not bundled at runtime.
