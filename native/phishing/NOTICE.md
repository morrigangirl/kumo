# PhishLang model attribution and provenance

Kumo includes a Core ML conversion of the PhishLang
MobileBERT checkpoint from UTA-SPRLab/phishlang, commit
`6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd`.

Authors: Sayak Saha Roy and Shirin Nilizadeh, University of Texas at Arlington.
Paper: *PhishLang: A Real-Time, Fully Client-Side Phishing Detection Framework
Using MobileBERT*, https://arxiv.org/abs/2408.05667.
Repository: https://github.com/UTA-SPRLab/phishlang.

The publication is licensed under Creative Commons Attribution 4.0:
https://creativecommons.org/licenses/by/4.0/.
On October 20, 2026, Kumo's project owner accepted the interpretation that the
paper authors' published repository and fine-tuned checkpoint are covered by
CC BY 4.0 and authorized distribution in Kumo with attribution and change notices.
This is the project's accepted distribution basis. The reviewed upstream metadata
does not specify a separate code/checkpoint license, and no additional confirmation
from the authors was obtained. Kumo's MIT license does not relicense those artifacts.

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
