## How A Company Will Use AEGISAI
Imagine a company is building a new AI model or AI agent.
Before the model is used by customers, employees, developers, or internal automation systems, the security team needs to answer one important question:
Is this model safe enough to release?
AEGISAI can be used as the security testing layer before that release.
A company can use AEGISAI to:
- Connect a new model to the lab.
- Run a repeatable safety test suite.
- Check how the model behaves under attack-style prompts.
- Store the exact prompt and response for every test.
- Review uncertain or risky outputs.
- Compare the new model with older versions.
- Generate a release decision before production use.
This makes the AI release process more structured and easier to explain to engineering, security, product, and leadership teams.
Model Release Workflow
A realistic model release workflow can look like this:
Step	What Happens	Why It Matters
1. Model is ready	The AI team creates or updates a model	The model is ready for security validation
2. Model is connected	The model is registered in AEGISAI	The lab can send tests to the model
3. Safety suite runs	AEGISAI sends adversarial prompts	The model is tested against real AI security risks
4. Evidence is captured	Prompts, responses, latency, risk, and severity are stored	Security team can review exact behavior
5. Findings are reviewed	Analysts review risky or uncertain outputs	Reduces false positives and confirms real issues
6. Scorecard is generated	AEGISAI calculates safety score and category scores	Gives a quick view of model safety
7. Release gate runs	The lab decides pass, fail, or manual review required	Helps prevent unsafe models from moving forward
8. Final decision is made	Team approves, blocks, or retests the model	Creates a repeatable release process


What AEGISAI Can Do Today
AEGISAI currently supports a working end-to-end AI security testing workflow.
Current Capabilities
- Connect to local Ollama models.
- Discover available local models.
- Register models for testing.
- Run individual security tests.
- Run a full safety suite.
- Use corpus-based test cases.
- Store test results in a database.
- Track risk status and severity.
- Track latency for each test.
- Group test results into campaigns.
- Review findings manually.
- Generate dashboard metrics.
- Generate model scorecards.
- Compare tested models.
- Check release readiness.
- View test results in a React dashboard.
- Show a demo video inside the dashboard.
This makes AEGISAI more than a simple prompt testing page. It is a working AI security lab with backend, frontend, database, review workflow, and release decision logic.
Security Areas Covered
AEGISAI currently focuses on practical AI security risks.
Security Area	What It Tests
Prompt Injection	Attempts to override or bypass model instructions
System Prompt Extraction	Attempts to reveal hidden or internal instructions
Sensitive Data Exposure	Attempts to reveal secrets, tokens, passwords, or keys
Jailbreak	Attempts to disable safety behavior or override policies
Privacy Leakage	Attempts to reveal private user data or memory
Tool Injection	Attempts to make the model trust malicious external instructions


How The Lab Works
AEGISAI sends controlled adversarial prompts to the selected model.
For each test, the lab records:
- Test ID
- Created time
- Model name
- Test type
- Test category
- Risk status
- Severity
- Latency
- Campaign ID
- Prompt sent
- Model response
- Finding
- Recommendation
- Review status
- Review notes
This gives the security team a clear trail of what was tested, how the model responded, and what decision was made.
#chatgpt-mermaid-_r_3h5_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-_r_3h5_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-_r_3h5_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-_r_3h5_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-_r_3h5_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-_r_3h5_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-_r_3h5_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-_r_3h5_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-_r_3h5_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-_r_3h5_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-_r_3h5_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-_r_3h5_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-_r_3h5_ p{margin:0;}#chatgpt-mermaid-_r_3h5_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-_r_3h5_ .label text,#chatgpt-mermaid-_r_3h5_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ .node rect,#chatgpt-mermaid-_r_3h5_ .node circle,#chatgpt-mermaid-_r_3h5_ .node ellipse,#chatgpt-mermaid-_r_3h5_ .node polygon,#chatgpt-mermaid-_r_3h5_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ .rough-node .label text,#chatgpt-mermaid-_r_3h5_ .node .label text,#chatgpt-mermaid-_r_3h5_ .image-shape .label,#chatgpt-mermaid-_r_3h5_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-_r_3h5_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ .rough-node .label,#chatgpt-mermaid-_r_3h5_ .node .label,#chatgpt-mermaid-_r_3h5_ .image-shape .label,#chatgpt-mermaid-_r_3h5_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-_r_3h5_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-_r_3h5_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-_r_3h5_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-_r_3h5_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-_r_3h5_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-_r_3h5_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-_r_3h5_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-_r_3h5_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-_r_3h5_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-_r_3h5_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-_r_3h5_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-_r_3h5_ .icon-shape,#chatgpt-mermaid-_r_3h5_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-_r_3h5_ .icon-shape p,#chatgpt-mermaid-_r_3h5_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-_r_3h5_ .icon-shape .label rect,#chatgpt-mermaid-_r_3h5_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-_r_3h5_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-_r_3h5_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-_r_3h5_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].node rect,#chatgpt-mermaid-_r_3h5_ [data-look="neo"].cluster rect,#chatgpt-mermaid-_r_3h5_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-_r_3h5_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-_r_3h5_-gradient);stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-_r_3h5_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-_r_3h5_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_3h5_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-_r_3h5_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_3h5_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-_r_3h5_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-_r_3h5_ .node tspan[font-weight="normal"],#chatgpt-mermaid-_r_3h5_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-_r_3h5_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ .node rect,#chatgpt-mermaid-_r_3h5_ .node circle,#chatgpt-mermaid-_r_3h5_ .node ellipse,#chatgpt-mermaid-_r_3h5_ .node polygon,#chatgpt-mermaid-_r_3h5_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-_r_3h5_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-_r_3h5_ .node.mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2,2;}#chatgpt-mermaid-_r_3h5_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-_r_3h5_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-_r_3h5_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}Select ModelRun Test SuiteCapture ResponseClassify RiskStore EvidenceReview ResultRelease Gate




Risk Status
AEGISAI classifies every result into a simple risk status.
Status	Meaning
Blocked	The model refused or safely handled the risky request
Uncertain	The model response needs human review
Leaked	The model appeared to reveal or accept unsafe behavior


This makes it easier to understand results quickly without reading every full response first.
Review Workflow
AI security testing cannot depend only on automation.
Some outputs need human judgment. AEGISAI includes a review workflow so a security analyst can make the final call.
Review Status	Meaning
Unreviewed	Finding has not been reviewed yet
Confirmed Safe	Analyst confirmed the response is safe
Confirmed Risky	Analyst confirmed this is a real issue
False Positive	Automated detection flagged it incorrectly
Needs Retest	The test should be improved or run again


This helps reduce noise and makes the results more useful for real security decisions.
Release Gate
AEGISAI includes a release gate to help decide whether a model is ready.
The release gate checks:
- Total number of tests
- Safety score
- Leaked findings
- High-risk findings
- Uncertain findings
- Unreviewed findings
- Confirmed risky findings
Decision	Meaning
Pass	Model meets the current safety requirements
Manual Review Required	Model needs analyst review before release
Fail	Model has serious safety issues


This gives the team a clear decision instead of only raw test results.
Dashboard
The frontend dashboard is built for a security engineer workflow.
It helps the user run tests, inspect results, review findings, and understand model release readiness.
Dashboard Includes
- Lab overview
- Demo video
- Safety score
- Passed, failed, and review metrics
- Run safety suite action
- Live testing view
- Latest results table
- Test detail viewer
- Analyst review workflow
- Model comparison
- Release gate summary
The dashboard is designed to make the lab easier to use for someone testing a model from start to finish.
Real-World Impact
AEGISAI can help teams save time and improve AI release safety.
Instead of manually testing a model with random prompts, the team gets a repeatable process.
AEGISAI can help with:
- Faster AI model security testing.
- Early detection of unsafe model behavior.
- Better evidence collection.
- Clearer analyst review.
- Safer model releases.
- Model-to-model comparison.
- Repeatable regression testing.
- Better communication between AI, security, and product teams.
As more companies build AI models and AI agents, a security lab like this can become part of the release process.
What I Will Add Next
AEGISAI is still growing. The next goal is to make it closer to a real AI security lab used by security teams.
Planned improvements:
- More advanced red-team test suites.
- More model provider support.
- AI agent testing.
- Tool-use and function-calling attack simulations.
- RAG security testing.
- Prompt injection datasets.
- Automated security reports.
- Model-to-model comparison reports.
- Compliance-style evidence export.
- Authentication and role-based access.
- CI/CD safety gates for AI releases.
- Stronger scoring and evaluation logic.
- Analyst collaboration features.
- Campaign history and trend tracking.
- Enterprise AI workflow testing.
The long-term goal is to make AEGISAI useful for testing new AI models, AI agents, and LLM-powered applications before they are released.
Tech Stack
Backend
- Python
- FastAPI
- SQLAlchemy
- SQLite or PostgreSQL
- Pydantic
- Uvicorn
- Ollama adapter
- Ruff
Frontend
- React
- TypeScript
- Vite
- CSS
- Fetch API
Local Model Runtime
- Ollama
- Local LLM models
Project Structure
aegisai/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── adapters.py
│   │   │   ├── model_registry.py
│   │   │   └── security_tests.py
│   │   ├── core/
│   │   │   └── database.py
│   │   ├── corpus/
│   │   │   └── basic_safety_suite.json
│   │   ├── db/
│   │   │   └── models.py
│   │   ├── models/
│   │   │   └── model_registry.py
│   │   ├── services/
│   │   │   └── ollama_adapter.py
│   │   └── main.py
│   └── scripts/
│       └── init_db.py
│
├── frontend/
│   ├── public/
│   │   └── demo.mp4
│   └── src/
│       ├── App.tsx
│       ├── App.css
│       └── main.tsx
│
└── README.md

How To Run The Lab
1. Start Ollama On Windows
Open Windows PowerShell:
$env:OLLAMA_HOST="0.0.0.0:11434"
ollama serve

Keep this terminal open.
2. Start Backend In WSL Ubuntu
Open Ubuntu terminal:
cd ~/projects/aegisai
source backend/.venv/bin/activate

WINDOWS_HOST=$(ip route | awk '/default/ {print $3}')
OLLAMA_BASE_URL=http://$WINDOWS_HOST:11434 uvicorn app.main:app --app-dir backend --reload

Backend runs at:
http://127.0.0.1:8000

3. Start Frontend
Open another Ubuntu terminal:
cd ~/projects/aegisai/frontend
npm run dev

Frontend runs at:
http://localhost:5173

Quick Verification
Check backend health:
curl http://127.0.0.1:8000/health

Check Ollama adapter:
curl http://127.0.0.1:8000/adapters/ollama/health

Run the basic safety suite:
curl -X POST http://127.0.0.1:8000/security-tests/suite/basic \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:3b"}'

View dashboard metrics:
curl http://127.0.0.1:8000/security-tests/dashboard

View latest results:
curl http://127.0.0.1:8000/security-tests/results

Compare tested models:
curl http://127.0.0.1:8000/security-tests/models/compare

Current Status
AEGISAI is currently a local AI security lab prototype.
It already supports:
- Local model testing
- Corpus-based safety suites
- Security result storage
- Campaign tracking
- Analyst review workflow
- Release gate logic
- Model comparison
- Dashboard UI
- Demo video integration
This is not only a dashboard. It is a working backend and frontend system for AI model security evaluation.
Long-Term Vision
The long-term vision for AEGISAI is to become a practical AI security lab for testing new models, AI agents, and LLM-powered applications.
When a company builds a new AI model, the question should not only be:
Does the model work?
The question should also be:
Is the model safe enough to release?
AEGISAI is built around that idea.
It gives teams a repeatable way to test AI behavior, collect evidence, review findings, compare models, and make safer release decisions.
Author
Built by Parakh Shinde
Cybersecurity fresher focused on AI Security, Red Teaming, SOC, Threat Detection, and practical security engineering.
