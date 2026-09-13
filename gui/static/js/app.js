/* =========================================================
   AI SECURITY LOG ANALYZER
   FRONTEND APPLICATION
   ========================================================= */

"use strict";


/* =========================================================
   GLOBAL STATE
   ========================================================= */

let currentJobId = null;
let selectedFile = null;
let currentResult = null;

let analysisRunning = false;
let aiRunning = false;

let progressTimer = null;
let realtimeTimer = null;

let realtimeRunning = false;
let realtimeEvents = [];

let lastRenderedAI = [];


/* =========================================================
   DOM HELPERS
   ========================================================= */

function $(id) {
    return document.getElementById(id);
}


function escapeHTML(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function safeArray(value) {
    return Array.isArray(value) ? value : [];
}


function safeObject(value) {
    return value && typeof value === "object" ? value : {};
}


/* =========================================================
   API HELPER
   ========================================================= */

async function apiRequest(url, options = {}) {

    const config = {
        method: options.method || "GET",
        ...options
    };

    if (!(config.body instanceof FormData)) {
        config.headers = {
            "Content-Type": "application/json",
            ...(options.headers || {})
        };
    }

    const response = await fetch(url, config);

    let data;

    try {
        data = await response.json();
    } catch (error) {
        data = {
            success: false,
            error: "Server returned an invalid response."
        };
    }

    if (!response.ok) {
        throw new Error(
            data.error ||
            data.message ||
            `Request failed with HTTP ${response.status}`
        );
    }

    return data;
}


/* =========================================================
   CLOCK
   ========================================================= */

function updateClock() {

    const now = new Date();

    const dateElement = $("current-date");
    const timeElement = $("current-time");

    if (dateElement) {
        dateElement.textContent =
            now.toLocaleDateString(undefined, {
                year: "numeric",
                month: "short",
                day: "2-digit"
            }).toUpperCase();
    }

    if (timeElement) {
        timeElement.textContent =
            now.toLocaleTimeString(undefined, {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false
            });
    }
}


/* =========================================================
   NAVIGATION
   ========================================================= */

function setupNavigation() {

    const navItems = document.querySelectorAll(".nav-item");

    navItems.forEach(button => {

        button.addEventListener("click", function(event) {

            event.preventDefault();

            const target =
                this.getAttribute("data-target");

            if (!target) {
                console.warn(
                    "Sidebar item has no data-target:",
                    this
                );
                return;
            }

            const section =
                document.getElementById(target);

            if (!section) {
                console.warn(
                    "Section not found:",
                    target
                );
                return;
            }

            navItems.forEach(item => {
                item.classList.remove("active");
            });

            this.classList.add("active");

            section.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        });

    });
}

/* =========================================================
   FILE UPLOAD
   ========================================================= */

function setupFileUpload() {

    const dropZone = $("drop-zone");
    const fileInput = $("file-input");
    const removeButton = $("remove-file");

    if (!dropZone || !fileInput) {
        return;
    }

    dropZone.addEventListener("click", event => {

        if (
            event.target === removeButton ||
            event.target.closest("#remove-file")
        ) {
            return;
        }

        fileInput.click();
    });


    fileInput.addEventListener("change", event => {

        const files = event.target.files;

        if (files && files.length > 0) {
            selectFile(files[0]);
        }
    });


    dropZone.addEventListener("dragover", event => {

        event.preventDefault();

        dropZone.classList.add("dragover");
    });


    dropZone.addEventListener("dragleave", () => {

        dropZone.classList.remove("dragover");
    });


    dropZone.addEventListener("drop", event => {

        event.preventDefault();

        dropZone.classList.remove("dragover");

        const files = event.dataTransfer.files;

        if (files && files.length > 0) {
            selectFile(files[0]);
        }
    });


    if (removeButton) {

        removeButton.addEventListener("click", event => {

            event.preventDefault();
            event.stopPropagation();

            clearSelectedFile();
        });
    }
}


/* =========================================================
   FILE SELECTION
   ========================================================= */

function selectFile(file) {

    const allowedExtensions = [
        ".log",
        ".txt",
        ".json",
        ".csv"
    ];

    const name = file.name.toLowerCase();

    const valid = allowedExtensions.some(
        extension => name.endsWith(extension)
    );

    if (!valid) {

        showUploadError(
            "Unsupported file type. Use .log, .txt, .json or .csv."
        );

        return;
    }

    if (file.size > 50 * 1024 * 1024) {

        showUploadError(
            "File is larger than the 50 MB upload limit."
        );

        return;
    }

    selectedFile = file;

    hideUploadError();

    const selectedContainer = $("selected-file");
    const fileName = $("selected-file-name");
    const fileInfo = $("selected-file-info");

    if (selectedContainer) {
        selectedContainer.style.display = "flex";
    }

    if (fileName) {
        fileName.textContent = file.name;
    }

    if (fileInfo) {
        fileInfo.textContent =
            `${formatBytes(file.size)} • ${file.type || "log file"}`;
    }

    const analyzeButton = $("analyze-button");

    if (analyzeButton) {
        analyzeButton.disabled = false;
    }
}


/* =========================================================
   CLEAR FILE
   ========================================================= */

function clearSelectedFile() {

    selectedFile = null;

    const fileInput = $("file-input");
    const selectedContainer = $("selected-file");

    if (fileInput) {
        fileInput.value = "";
    }

    if (selectedContainer) {
        selectedContainer.style.display = "none";
    }

    const analyzeButton = $("analyze-button");

    if (analyzeButton) {
        analyzeButton.disabled = true;
    }

    hideUploadError();
}


/* =========================================================
   FILE SIZE
   ========================================================= */

function formatBytes(bytes) {

    if (!bytes || bytes <= 0) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];

    const index =
        Math.floor(
            Math.log(bytes) / Math.log(1024)
        );

    const safeIndex =
        Math.min(index, units.length - 1);

    return (
        bytes / Math.pow(1024, safeIndex)
    ).toFixed(safeIndex === 0 ? 0 : 2)
        + " "
        + units[safeIndex];
}


/* =========================================================
   UPLOAD ERRORS
   ========================================================= */

function showUploadError(message) {

    const element = $("upload-error");

    if (!element) {
        return;
    }

    element.textContent = message;

    element.style.display = "block";
}


function hideUploadError() {

    const element = $("upload-error");

    if (element) {
        element.style.display = "none";
    }
}


/* =========================================================
   MODEL MANAGEMENT
   ========================================================= */

async function loadModels() {

    try {

        const data = await apiRequest("/models");

        const models = safeArray(data.models);

        const select = $("ai-model");

        if (!select) {
            return;
        }

        select.innerHTML = "";

        if (models.length === 0) {

            const option = document.createElement("option");

            option.value = "qwen3:1.7b";
            option.textContent = "qwen3:1.7b";

            select.appendChild(option);

            return;
        }

        models.forEach(model => {

            const option = document.createElement("option");

            option.value = model;
            option.textContent = model;

            select.appendChild(option);
        });

        const preferred =
            "qwen3:1.7b";

        if (models.includes(preferred)) {
            select.value = preferred;
        }

    } catch (error) {

        console.error(
            "Model loading failed:",
            error
        );
    }
}


/* =========================================================
   HEALTH CHECK
   ========================================================= */

async function checkHealth() {

    const sidebarStatus = $("sidebar-ai-status");
    const systemBadge = $("system-badge");

    try {

        const data = await apiRequest("/health");

        const online =
            data.status === "online";

        const aiAvailable =
            data.ai_available === true;

        if (sidebarStatus) {

            if (aiAvailable) {

                sidebarStatus.textContent =
                    "OLLAMA AI ONLINE";

                sidebarStatus.className =
                    "status-badge online";

            } else {

                sidebarStatus.textContent =
                    "AI OFFLINE";

                sidebarStatus.className =
                    "status-badge danger";
            }
        }

        if (systemBadge) {

            if (online) {

                systemBadge.textContent =
                    "SYSTEM ONLINE";

                systemBadge.className =
                    "status-badge online";

            } else {

                systemBadge.textContent =
                    "SYSTEM OFFLINE";

                systemBadge.className =
                    "status-badge danger";
            }
        }

    } catch (error) {

        console.error(
            "Health check failed:",
            error
        );

        if (sidebarStatus) {

            sidebarStatus.textContent =
                "AI OFFLINE";

            sidebarStatus.className =
                "status-badge danger";
        }

        if (systemBadge) {

            systemBadge.textContent =
                "BACKEND OFFLINE";

            systemBadge.className =
                "status-badge danger";
        }
    }
}


/* =========================================================
   START ANALYSIS
   ========================================================= */

async function startAnalysis() {

    if (!selectedFile) {

        showUploadError(
            "Select a log file first."
        );

        return;
    }

    if (analysisRunning) {
        return;
    }

    analysisRunning = true;

    hideUploadError();

    setAnalysisButtonState(true);

    resetResults();

    setProgress(
        5,
        "Uploading log file..."
    );

    try {

        const formData = new FormData();

        formData.append(
            "log_file",
            selectedFile
        );

        const modelSelect = $("ai-model");

        if (modelSelect && modelSelect.value) {

            formData.append(
                "model",
                modelSelect.value
            );
        }

        const data = await apiRequest(
            "/analyze",
            {
                method: "POST",
                body: formData
            }
        );

        if (!data.success) {

            throw new Error(
                data.error ||
                "Analysis could not be started."
            );
        }

        currentJobId =
            data.job_id ||
            data.id;

        if (!currentJobId) {

            throw new Error(
                "Backend did not return a job ID."
            );
        }

        setProgress(
            10,
            "Analysis job started..."
        );

        pollAnalysisStatus();

    } catch (error) {

        analysisRunning = false;

        setAnalysisButtonState(false);

        setProgress(
            0,
            "Analysis failed."
        );

        showUploadError(
            error.message
        );

        console.error(
            "Analysis error:",
            error
        );
    }
}


/* =========================================================
   POLL ANALYSIS STATUS
   ========================================================= */

async function pollAnalysisStatus() {

    if (!currentJobId) {
        return;
    }

    try {

        const data = await apiRequest(
            `/status/${encodeURIComponent(currentJobId)}`
        );

        const progress =
            Number(data.progress || 0);

        const status =
            String(
                data.status ||
                data.state ||
                ""
            ).toLowerCase();

        const message =
            data.message ||
            data.status_message ||
            "Processing...";

        setProgress(
            progress,
            message
        );

        if (
            status === "complete" ||
            status === "completed" ||
            status === "done" ||
            progress >= 100
        ) {

            await finishAnalysis();

            return;
        }

        if (
            status === "error" ||
            status === "failed"
        ) {

            throw new Error(
                data.error ||
                data.message ||
                "Analysis job failed."
            );
        }

        clearTimeout(progressTimer);

        progressTimer = setTimeout(
            pollAnalysisStatus,
            1000
        );

    } catch (error) {

        analysisRunning = false;

        setAnalysisButtonState(false);

        setProgress(
            0,
            "Analysis failed."
        );

        showUploadError(
            error.message
        );

        console.error(
            "Status polling error:",
            error
        );
    }
}


/* =========================================================
   FINISH ANALYSIS
   ========================================================= */

async function finishAnalysis() {

    try {

        setProgress(
            95,
            "Loading analysis results..."
        );

        const data = await apiRequest(
            `/results/${encodeURIComponent(currentJobId)}`
        );

        if (!data.success) {

            throw new Error(
                data.error ||
                "Could not load analysis results."
            );
        }

        currentResult =
            data.result ||
            data.results ||
            data;

        renderResults(
            currentResult
        );

        setProgress(
            100,
            "Analysis complete."
        );

        analysisRunning = false;

        setAnalysisButtonState(false);

        scrollToSection("overview");

    } catch (error) {

        analysisRunning = false;

        setAnalysisButtonState(false);

        setProgress(
            0,
            "Could not load results."
        );

        showUploadError(
            error.message
        );

        console.error(
            "Result loading error:",
            error
        );
    }
}


/* =========================================================
   ANALYSIS BUTTON STATE
   ========================================================= */

function setAnalysisButtonState(running) {

    const button = $("analyze-button");

    if (!button) {
        return;
    }

    button.disabled =
        running ||
        !selectedFile;

    if (running) {

        button.textContent =
            "ANALYZING...";

    } else {

        button.textContent =
            "RUN ANALYSIS";
    }
}


/* =========================================================
   PROGRESS
   ========================================================= */

function setProgress(percent, message) {

    const percentElement =
        $("progress-percent");

    const bar =
        $("progress-bar");

    const messageElement =
        $("progress-message");

    const safePercent =
        Math.max(
            0,
            Math.min(
                100,
                Number(percent) || 0
            )
        );

    if (percentElement) {

        percentElement.textContent =
            `${Math.round(safePercent)}%`;
    }

    if (bar) {

        bar.style.width =
            `${safePercent}%`;
    }

    if (messageElement && message) {

        messageElement.textContent =
            message;
    }
}


/* =========================================================
   RESET RESULTS
   ========================================================= */

function resetResults() {

    currentResult = null;

    lastRenderedAI = [];

    setMetric(
        "metric-events",
        0
    );

    setMetric(
        "metric-detections",
        0
    );

    setMetric(
        "metric-incidents",
        0
    );

    setMetric(
        "metric-ai",
        0
    );

    renderEmpty(
        "detections-container",
        "NO DETECTIONS",
        "Run an analysis to populate security detections."
    );

    renderEmpty(
        "incidents-container",
        "NO INCIDENTS",
        "Security incidents will appear here after correlation."
    );

    renderEmpty(
        "threat-intelligence-container",
        "NO THREAT INTELLIGENCE",
        "Threat intelligence results will appear here when available."
    );

    renderEmpty(
        "ai-analysis-container",
        "AI ANALYSIS NOT RUN",
        "Run analysis or use the AI SOC Analysis button."
    );

    renderEmpty(
        "report-content",
        "REPORT NOT AVAILABLE",
        "Run a log analysis to generate the security report."
    );

    const aiStatus = $("ai-section-status");

    if (aiStatus) {
        aiStatus.textContent =
            "WAITING FOR ANALYSIS";
    }
}


/* =========================================================
   RENDER COMPLETE RESULTS
   ========================================================= */

function renderResults(result) {

    result =
        safeObject(result);

    currentResult = result;

    const events =
        safeArray(
            result.events
        );

    const detections =
        safeArray(
            result.detections
        );

    const incidents =
        safeArray(
            result.incidents
        );

    const ai =
        safeArray(
            result.ai_analysis ||
            result.ai_results
        );

    setMetric(
        "metric-events",
        events.length ||
        Number(result.event_count || 0)
    );

    setMetric(
        "metric-detections",
        detections.length ||
        Number(result.detection_count || 0)
    );

    setMetric(
        "metric-incidents",
        incidents.length ||
        Number(result.incident_count || 0)
    );

    setMetric(
        "metric-ai",
        ai.length
    );

    renderDetections(
        detections
    );

    renderIncidents(
        incidents
    );

    renderThreatIntelligence(
        incidents
    );

    renderAIAnalysis(
        ai
    );

    renderReport(
        result
    );
}


/* =========================================================
   METRIC HELPER
   ========================================================= */

function setMetric(id, value) {

    const element = $(id);

    if (element) {
        element.textContent =
            Number(value || 0).toLocaleString();
    }
}


/* =========================================================
   DETECTIONS
   ========================================================= */

function renderDetections(detections) {

    const container =
        $("detections-container");

    if (!container) {
        return;
    }

    if (!detections.length) {

        renderEmpty(
            "detections-container",
            "NO DETECTIONS",
            "No detection rules were triggered."
        );

        return;
    }

    container.innerHTML =
        detections.map(
            (detection, index) => {

                const item =
                    safeObject(detection);

                const severity =
                    normalizeSeverity(
                        item.severity
                    );

                const title =
                    item.title ||
                    item.rule_name ||
                    item.name ||
                    item.detection ||
                    `Detection ${index + 1}`;

                const description =
                    item.description ||
                    item.message ||
                    item.reason ||
                    "Security detection triggered.";

                const sourceIP =
                    item.source_ip ||
                    item.src_ip ||
                    "";

                const eventType =
                    item.event_type ||
                    item.type ||
                    "";

                return `
                    <article class="detection-card">

                        <div class="detection-header">

                            <div class="detection-title">
                                ${escapeHTML(title)}
                            </div>

                            <span class="severity-badge severity-${severity.toLowerCase()}">
                                ${escapeHTML(severity)}
                            </span>

                        </div>

                        <div class="detection-description">
                            ${escapeHTML(description)}
                        </div>

                        <div class="incident-meta">

                            ${
                                sourceIP
                                    ? `
                                        <span class="meta-item">
                                            SOURCE ${escapeHTML(sourceIP)}
                                        </span>
                                      `
                                    : ""
                            }

                            ${
                                eventType
                                    ? `
                                        <span class="meta-item">
                                            TYPE ${escapeHTML(eventType)}
                                        </span>
                                      `
                                    : ""
                            }

                            <span class="meta-item">
                                DETECTION #${index + 1}
                            </span>

                        </div>

                    </article>
                `;
            }
        ).join("");
}


/* =========================================================
   INCIDENTS
   ========================================================= */

function renderIncidents(incidents) {

    const container =
        $("incidents-container");

    if (!container) {
        return;
    }

    if (!incidents.length) {

        renderEmpty(
            "incidents-container",
            "NO INCIDENTS",
            "No correlated security incidents were created."
        );

        return;
    }

    container.innerHTML =
        incidents.map(
            (incident, index) => {

                const item =
                    safeObject(incident);

                const severity =
                    normalizeSeverity(
                        item.severity
                    );

                const sourceIP =
                    item.source_ip ||
                    "Unknown";

                const risk =
                    item.risk_score ??
                    item.risk ??
                    0;

                const count =
                    item.detection_count ??
                    safeArray(
                        item.detections
                    ).length;

                const attackTypes =
                    safeArray(
                        item.attack_types
                    );

                const summary =
                    item.summary ||
                    "Suspicious activity correlated into a security incident.";

                const incidentID =
                    item.incident_id ||
                    `INC-${String(index + 1).padStart(3, "0")}`;

                return `
                    <article class="incident-card">

                        <div class="incident-header">

                            <div class="incident-title">
                                ${escapeHTML(incidentID)}
                            </div>

                            <span class="severity-badge severity-${severity.toLowerCase()}">
                                ${escapeHTML(severity)}
                            </span>

                        </div>

                        <div class="incident-summary">
                            ${escapeHTML(summary)}
                        </div>

                        <div class="incident-meta">

                            <span class="meta-item">
                                SOURCE ${escapeHTML(sourceIP)}
                            </span>

                            <span class="meta-item">
                                RISK ${escapeHTML(risk)}
                            </span>

                            <span class="meta-item">
                                DETECTIONS ${escapeHTML(count)}
                            </span>

                        </div>

                        ${
                            attackTypes.length
                                ? `
                                    <div class="attack-tags">

                                        ${
                                            attackTypes.map(
                                                attack => `
                                                    <span class="attack-tag">
                                                        ${escapeHTML(attack)}
                                                    </span>
                                                `
                                            ).join("")
                                        }

                                    </div>
                                  `
                                : ""
                        }

                    </article>
                `;
            }
        ).join("");
}


/* =========================================================
   THREAT INTELLIGENCE
   ========================================================= */

function renderThreatIntelligence(incidents) {

    const container =
        $("threat-intelligence-container");

    if (!container) {
        return;
    }

    const enriched = incidents.filter(
        incident => {

            const ti =
                incident &&
                (
                    incident.threat_intelligence ||
                    incident.ti ||
                    incident.abuseipdb
                );

            return ti &&
                Object.keys(
                    safeObject(ti)
                ).length > 0;
        }
    );

    if (!enriched.length) {

        renderEmpty(
            "threat-intelligence-container",
            "NO TI DATA",
            "No threat-intelligence enrichment is available for the current incidents."
        );

        return;
    }

    container.innerHTML =
        enriched.map(
            (incident, index) => {

                const ti =
                    incident.threat_intelligence ||
                    incident.ti ||
                    incident.abuseipdb ||
                    {};

                const ip =
                    incident.source_ip ||
                    ti.ip ||
                    "Unknown";

                const classification =
                    ti.classification ||
                    ti.usage_type ||
                    ti.domain ||
                    "Unknown";

                const reputation =
                    ti.reputation ??
                    ti.abuse_confidence_score ??
                    ti.confidence_score ??
                    "N/A";

                const country =
                    ti.country_code ||
                    ti.country ||
                    "N/A";

                const reports =
                    ti.total_reports ??
                    ti.reports ??
                    "N/A";

                return `
                    <article class="ti-card">

                        <div class="ti-header">

                            <div class="ti-title">
                                ${escapeHTML(ip)}
                            </div>

                            <span class="severity-badge severity-medium">
                                TI ENRICHED
                            </span>

                        </div>

                        <div class="ti-description">

                            External intelligence was found for this source.

                        </div>

                        <div class="incident-meta">

                            <span class="meta-item">
                                CLASS ${escapeHTML(classification)}
                            </span>

                            <span class="meta-item">
                                REPUTATION ${escapeHTML(reputation)}
                            </span>

                            <span class="meta-item">
                                COUNTRY ${escapeHTML(country)}
                            </span>

                            <span class="meta-item">
                                REPORTS ${escapeHTML(reports)}
                            </span>

                        </div>

                    </article>
                `;
            }
        ).join("");
}


/* =========================================================
   AI ANALYSIS
   ========================================================= */

function renderAIAnalysis(aiResults) {

    const container =
        $("ai-analysis-container");

    const status =
        $("ai-section-status");

    if (!container) {
        return;
    }

    lastRenderedAI =
        safeArray(aiResults);

    if (!aiResults.length) {

        if (status) {
            status.textContent =
                "NO AI ANALYSIS";
        }

        renderEmpty(
            "ai-analysis-container",
            "AI ANALYSIS NOT AVAILABLE",
            "No incident analysis has been generated yet."
        );

        return;
    }

    if (status) {
        status.textContent =
            `${aiResults.length} ANALYSIS RESULT${aiResults.length === 1 ? "" : "S"}`;
    }

    container.innerHTML =
        aiResults.map(
            (result, index) => {

                const item =
                    safeObject(result);

                const model =
                    item.model ||
                    "Unknown model";

                const analysis =
                    item.analysis ||
                    "";

                const skipped =
                    item.skipped === true;

                const success =
                    item.success !== false;

                const error =
                    item.error ||
                    "";

                if (skipped) {

                    return `
                        <article class="ai-analysis-card">

                            <div class="ai-analysis-header">

                                <strong>
                                    AI ANALYSIS #${index + 1}
                                </strong>

                                <span>
                                    ${escapeHTML(model)}
                                </span>

                            </div>

                            <div class="ai-analysis-content">

                                <div class="ai-verdict">
                                    ${escapeHTML(
                                        analysis ||
                                        "AI analysis skipped."
                                    )}
                                </div>

                            </div>

                        </article>
                    `;
                }

                if (!success) {

                    return `
                        <article class="ai-analysis-card">

                            <div class="ai-analysis-header">

                                <strong>
                                    AI ANALYSIS FAILED
                                </strong>

                                <span>
                                    ${escapeHTML(model)}
                                </span>

                            </div>

                            <div class="ai-analysis-content">

                                <div class="ai-verdict">
                                    ${escapeHTML(
                                        error ||
                                        "The AI provider returned an error."
                                    )}
                                </div>

                            </div>

                        </article>
                    `;
                }

                return `
                    <article class="ai-analysis-card">

                        <div class="ai-analysis-header">

                            <strong>
                                AI SOC ANALYST #${index + 1}
                            </strong>

                            <span>
                                ${escapeHTML(model)}
                            </span>

                        </div>

                        <div class="ai-analysis-content">
                            ${formatAIText(analysis)}
                        </div>

                    </article>
                `;
            }
        ).join("");
}


/* =========================================================
   FORMAT AI TEXT
   ========================================================= */

function formatAIText(text) {

    if (!text) {

        return `
            <div class="ai-verdict">
                AI returned an empty analysis.
            </div>
        `;
    }

    let html =
        escapeHTML(text);

    /*
     * Convert common SOC report headings into
     * readable dashboard sections.
     */

    const headings = [
        "VERDICT",
        "ATTACK ANALYSIS",
        "MITRE ATT&CK",
        "KEY EVIDENCE",
        "RECOMMENDED RESPONSE",
        "CONFIDENCE",
        "LIMITATIONS"
    ];

    headings.forEach(
        heading => {

            const escaped =
                escapeHTML(heading);

            const pattern =
                new RegExp(
                    `(^|\\n)\\s*${escaped}\\s*:?`,
                    "gi"
                );

            html =
                html.replace(
                    pattern,
                    `$1<h4>${escaped}</h4>`
                );
        }
    );

    html =
        html.replace(
            /\n\s*[-*]\s+/g,
            "\n• "
        );

    html =
        html.replace(
            /\n/g,
            "<br>"
        );

    return html;
}


/* =========================================================
   RUN AI ONLY
   ========================================================= */

async function runAIOnly() {

    if (aiRunning) {
        return;
    }

    if (!currentResult) {

        setAIStatus(
            "RUN A LOG ANALYSIS FIRST"
        );

        return;
    }

    const incidents =
        safeArray(
            currentResult.incidents
        );

    if (!incidents.length) {

        setAIStatus(
            "NO INCIDENTS AVAILABLE"
        );

        renderEmpty(
            "ai-analysis-container",
            "NO INCIDENTS",
            "AI analysis requires at least one security incident."
        );

        return;
    }

    aiRunning = true;

    const button =
        $("ai-run-button");

    if (button) {

        button.disabled = true;

        button.textContent =
            "AI ANALYZING...";
    }

    setAIStatus(
        "AI ANALYSIS RUNNING..."
    );

    try {

        const modelSelect =
            $("ai-model");

        const model =
            modelSelect &&
            modelSelect.value
                ? modelSelect.value
                : null;

        const data =
            await apiRequest(
                "/ai/analyze",
                {
                    method: "POST",
                    body: JSON.stringify({
                        incidents,
                        model
                    })
                }
            );

        if (!data.success) {

            throw new Error(
                data.error ||
                "AI analysis failed."
            );
        }

        const aiResults =
            safeArray(
                data.ai_analysis
            );

        currentResult.ai_analysis =
            aiResults;

        renderAIAnalysis(
            aiResults
        );

        setMetric(
            "metric-ai",
            aiResults.length
        );

        renderReport(
            currentResult
        );

        setAIStatus(
            `${aiResults.length} AI RESULT${aiResults.length === 1 ? "" : "S"} GENERATED`
        );

    } catch (error) {

        console.error(
            "AI analysis error:",
            error
        );

        setAIStatus(
            "AI ANALYSIS FAILED"
        );

        renderEmpty(
            "ai-analysis-container",
            "AI ERROR",
            error.message
        );

    } finally {

        aiRunning = false;

        if (button) {

            button.disabled = false;

            button.textContent =
                "RUN AI SOC ANALYSIS";
        }
    }
}


/* =========================================================
   AI STATUS
   ========================================================= */

function setAIStatus(message) {

    const element =
        $("ai-section-status");

    if (element) {
        element.textContent =
            message;
    }
}


/* =========================================================
   REPORT RENDERER
   ========================================================= */

function renderReport(result) {

    const container =
        $("report-content");

    if (!container) {
        return;
    }

    result =
        safeObject(result);

    const events =
        safeArray(
            result.events
        );

    const detections =
        safeArray(
            result.detections
        );

    const incidents =
        safeArray(
            result.incidents
        );

    const aiResults =
        safeArray(
            result.ai_analysis ||
            result.ai_results
        );

    if (
        !events.length &&
        !detections.length &&
        !incidents.length
    ) {

        renderEmpty(
            "report-content",
            "REPORT NOT AVAILABLE",
            "Run a log analysis to generate the security report."
        );

        return;
    }

    const severityCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };

    detections.forEach(
        detection => {

            const severity =
                normalizeSeverity(
                    detection.severity
                );

            if (
                Object.prototype.hasOwnProperty.call(
                    severityCounts,
                    severity
                )
            ) {
                severityCounts[severity]++;
            }
        }
    );

    const highestSeverity =
        getHighestSeverity(
            incidents
        );

    const sourceIPs =
        [
            ...new Set(
                incidents
                    .map(
                        incident =>
                            incident.source_ip
                    )
                    .filter(Boolean)
            )
        ];

    container.innerHTML = `

        <div class="report-panel">

            <div class="report-header">

                <div>

                    <h4>
                        SECURITY ANALYSIS REPORT
                    </h4>

                    <span>
                        Generated ${escapeHTML(
                            new Date().toLocaleString()
                        )}
                    </span>

                </div>

                <span class="status-badge ${
                    incidents.length
                        ? "danger"
                        : "online"
                }">

                    ${
                        incidents.length
                            ? "THREATS DETECTED"
                            : "NO ACTIVE INCIDENTS"
                    }

                </span>

            </div>


            <div class="report-metrics">

                <div class="report-metric">

                    <strong>
                        ${events.length}
                    </strong>

                    <span>
                        EVENTS
                    </span>

                </div>

                <div class="report-metric">

                    <strong>
                        ${detections.length}
                    </strong>

                    <span>
                        DETECTIONS
                    </span>

                </div>

                <div class="report-metric">

                    <strong>
                        ${incidents.length}
                    </strong>

                    <span>
                        INCIDENTS
                    </span>

                </div>

                <div class="report-metric">

                    <strong>
                        ${aiResults.length}
                    </strong>

                    <span>
                        AI ANALYSES
                    </span>

                </div>

            </div>


            <div class="report-section">

                <h5>
                    SEVERITY DISTRIBUTION
                </h5>

                <div class="report-severity-grid">

                    <div>
                        <strong>
                            ${severityCounts.CRITICAL}
                        </strong>
                        <span>CRITICAL</span>
                    </div>

                    <div>
                        <strong>
                            ${severityCounts.HIGH}
                        </strong>
                        <span>HIGH</span>
                    </div>

                    <div>
                        <strong>
                            ${severityCounts.MEDIUM}
                        </strong>
                        <span>MEDIUM</span>
                    </div>

                    <div>
                        <strong>
                            ${severityCounts.LOW}
                        </strong>
                        <span>LOW</span>
                    </div>

                    <div>
                        <strong>
                            ${severityCounts.INFO}
                        </strong>
                        <span>INFO</span>
                    </div>

                </div>

            </div>


            <div class="report-section">

                <h5>
                    INCIDENT OVERVIEW
                </h5>

                ${
                    incidents.length
                        ? incidents.map(
                            (incident, index) => {

                                const severity =
                                    normalizeSeverity(
                                        incident.severity
                                    );

                                const incidentID =
                                    incident.incident_id ||
                                    `INC-${String(index + 1).padStart(3, "0")}`;

                                const sourceIP =
                                    incident.source_ip ||
                                    "Unknown";

                                const risk =
                                    incident.risk_score ??
                                    incident.risk ??
                                    0;

                                const summary =
                                    incident.summary ||
                                    "No incident summary available.";

                                return `

                                    <div class="report-incident">

                                        <div>

                                            <strong>
                                                ${escapeHTML(
                                                    incidentID
                                                )}
                                            </strong>

                                            <span>
                                                ${escapeHTML(
                                                    severity
                                                )}
                                            </span>

                                        </div>

                                        <div>

                                            <span>
                                                SOURCE:
                                                ${escapeHTML(
                                                    sourceIP
                                                )}
                                            </span>

                                            <span>
                                                RISK:
                                                ${escapeHTML(
                                                    risk
                                                )}
                                            </span>

                                        </div>

                                        <p>
                                            ${escapeHTML(
                                                summary
                                            )}
                                        </p>

                                    </div>

                                `;
                            }
                        ).join("")
                        : `
                            <div class="report-incident">
                                <div>
                                    <strong>
                                        No incidents detected
                                    </strong>
                                </div>
                            </div>
                          `
                }

            </div>


            <div class="report-section">

                <h5>
                    ANALYSIS STATUS
                </h5>

                <div class="report-status">

                    <span>
                        Highest Severity
                    </span>

                    <strong>
                        ${escapeHTML(
                            highestSeverity
                        )}
                    </strong>

                </div>

                <div class="report-status">

                    <span>
                        Unique Source IPs
                    </span>

                    <strong>
                        ${sourceIPs.length}
                    </strong>

                </div>

                <div class="report-status">

                    <span>
                        AI Analysis
                    </span>

                    <strong>
                        ${
                            aiResults.length
                                ? "AVAILABLE"
                                : "NOT RUN"
                        }
                    </strong>

                </div>

                <div class="report-status">

                    <span>
                        Threat Assessment
                    </span>

                    <strong>
                        ${
                            incidents.length
                                ? "INVESTIGATION REQUIRED"
                                : "NO INCIDENTS"
                        }
                    </strong>

                </div>

            </div>

        </div>
    `;
}


/* =========================================================
   HIGHEST SEVERITY
   ========================================================= */

function getHighestSeverity(incidents) {

    const order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO"
    ];

    let highest =
        "INFO";

    incidents.forEach(
        incident => {

            const severity =
                normalizeSeverity(
                    incident.severity
                );

            if (
                order.indexOf(severity) <
                order.indexOf(highest)
            ) {
                highest = severity;
            }
        }
    );

    return highest;
}


/* =========================================================
   NORMALIZE SEVERITY
   ========================================================= */

function normalizeSeverity(value) {

    const severity =
        String(
            value ||
            "INFO"
        )
        .trim()
        .toUpperCase();

    if (
        [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"
        ].includes(severity)
    ) {
        return severity;
    }

    return "INFO";
}


/* =========================================================
   EMPTY STATE
   ========================================================= */

function renderEmpty(
    containerId,
    title,
    message
) {

    const container =
        $(containerId);

    if (!container) {
        return;
    }

    container.innerHTML = `

        <div class="empty-state">

            <div class="empty-icon">
                —
            </div>

            <strong>
                ${escapeHTML(title)}
            </strong>

            <span>
                ${escapeHTML(message)}
            </span>

        </div>
    `;
}


/* =========================================================
   REALTIME CONTROLS
   ========================================================= */

function setupRealtimeControls() {

    const startButton =
        $("realtime-start");

    const stopButton =
        $("realtime-stop");

    if (startButton) {

        startButton.addEventListener(
            "click",
            startRealtimeMonitor
        );
    }

    if (stopButton) {

        stopButton.addEventListener(
            "click",
            stopRealtimeMonitor
        );
    }
}


/* =========================================================
   START REALTIME
   ========================================================= */

async function startRealtimeMonitor() {

    if (realtimeRunning) {
        return;
    }

    const logInput =
        $("realtime-log-path");

    const path =
        logInput
            ? logInput.value.trim()
            : "";

    if (!path) {

        setRealtimeStatus(
            "ENTER LOG PATH"
        );

        return;
    }

    try {

        const data =
            await apiRequest(
                "/realtime/start",
                {
                    method: "POST",
                    body: JSON.stringify({
                        log_file: path
                    })
                }
            );

        if (!data.success) {

            throw new Error(
                data.error ||
                "Realtime monitor could not start."
            );
        }

        realtimeRunning = true;

        realtimeEvents = [];

        updateRealtimeButtons();

        setRealtimeStatus(
            "REALTIME MONITOR ONLINE"
        );

        startRealtimePolling();

    } catch (error) {

        console.error(
            "Realtime start error:",
            error
        );

        setRealtimeStatus(
            error.message
        );
    }
}


/* =========================================================
   STOP REALTIME
   ========================================================= */

async function stopRealtimeMonitor() {

    try {

        await apiRequest(
            "/realtime/stop",
            {
                method: "POST",
                body: JSON.stringify({})
            }
        );

    } catch (error) {

        console.error(
            "Realtime stop error:",
            error
        );

    } finally {

        realtimeRunning = false;

        clearTimeout(
            realtimeTimer
        );

        realtimeTimer = null;

        updateRealtimeButtons();

        setRealtimeStatus(
            "REALTIME MONITOR STOPPED"
        );
    }
}


/* =========================================================
   REALTIME POLLING
   ========================================================= */

function startRealtimePolling() {

    clearTimeout(
        realtimeTimer
    );

    pollRealtime();

}


/* =========================================================
   POLL REALTIME
   ========================================================= */

async function pollRealtime() {

    if (!realtimeRunning) {
        return;
    }

    try {

        const status =
            await apiRequest(
                "/realtime/status"
            );

        renderRealtimeStatus(
            status
        );

        const events =
            await apiRequest(
                "/realtime/events"
            );

        const newEvents =
            safeArray(
                events.events
            );

        if (newEvents.length) {

            realtimeEvents =
                newEvents;

            renderRealtimeEvents(
                newEvents
            );
        }

    } catch (error) {

        console.error(
            "Realtime polling error:",
            error
        );
    }

    if (realtimeRunning) {

        realtimeTimer =
            setTimeout(
                pollRealtime,
                1500
            );
    }
}


/* =========================================================
   REALTIME STATUS
   ========================================================= */

function renderRealtimeStatus(data) {

    const stats =
        safeObject(
            data.stats ||
            data
        );

    setMetric(
        "realtime-events",
        stats.events ??
        stats.event_count ??
        0
    );

    setMetric(
        "realtime-detections",
        stats.detections ??
        stats.detection_count ??
        0
    );

    setMetric(
        "realtime-incidents",
        stats.incidents ??
        stats.incident_count ??
        0
    );

    setMetric(
        "realtime-ai",
        stats.ai ??
        stats.ai_count ??
        0
    );

    const statusText =
        stats.status ||
        data.status;

    if (statusText) {

        setRealtimeStatus(
            String(statusText).toUpperCase()
        );
    }
}


/* =========================================================
   REALTIME EVENTS
   ========================================================= */

function renderRealtimeEvents(events) {

    const container =
        $("realtime-events");

    if (!container) {
        return;
    }

    if (!events.length) {

        renderEmpty(
            "realtime-events",
            "NO LIVE EVENTS",
            "Waiting for events from the realtime log monitor."
        );

        return;
    }

    const visible =
        events.slice(-100).reverse();

    container.innerHTML =
        visible.map(
            event => {

                const item =
                    safeObject(event);

                const timestamp =
                    item.timestamp ||
                    item.time ||
                    new Date().toLocaleTimeString();

                const message =
                    item.message ||
                    item.raw_log ||
                    item.raw ||
                    JSON.stringify(item);

                return `

                    <div class="live-event">

                        <small>
                            ${escapeHTML(timestamp)}
                        </small>

                        <p>
                            ${escapeHTML(message)}
                        </p>

                    </div>

                `;
            }
        ).join("");
}


/* =========================================================
   REALTIME BUTTON STATE
   ========================================================= */

function updateRealtimeButtons() {

    const startButton =
        $("realtime-start");

    const stopButton =
        $("realtime-stop");

    if (startButton) {
        startButton.disabled =
            realtimeRunning;
    }

    if (stopButton) {
        stopButton.disabled =
            !realtimeRunning;
    }
}


/* =========================================================
   REALTIME STATUS MESSAGE
   ========================================================= */

function setRealtimeStatus(message) {

    const element =
        $("realtime-status");

    if (element) {
        element.textContent =
            message;
    }
}


/* =========================================================
   SCROLL TO SECTION
   ========================================================= */

function scrollToSection(id) {

    const section =
        $(id);

    if (!section) {
        return;
    }

    section.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


/* =========================================================
   RESET BUTTON
   ========================================================= */

function setupResetButton() {

    const button =
        $("reset-button");

    if (!button) {
        return;
    }

    button.addEventListener(
        "click",
        () => {

            clearSelectedFile();

            currentJobId = null;

            resetResults();

            setProgress(
                0,
                "Ready for analysis."
            );

            hideUploadError();
        }
    );
}


/* =========================================================
   BUTTONS
   ========================================================= */

function setupMainButtons() {

    const analyzeButton =
        $("analyze-button");

    const aiButton =
        $("ai-run-button");

    if (analyzeButton) {

        analyzeButton.addEventListener(
            "click",
            startAnalysis
        );
    }

    if (aiButton) {

        aiButton.addEventListener(
            "click",
            runAIOnly
        );
    }
}


/* =========================================================
   INITIALIZATION
   ========================================================= */

async function initializeApp() {

    updateClock();

    setInterval(
        updateClock,
        1000
    );

    setupNavigation();

    setupFileUpload();

    setupRealtimeControls();

    setupMainButtons();

    setupResetButton();

    updateRealtimeButtons();

    clearSelectedFile();

    resetResults();

    await Promise.all([
        checkHealth(),
        loadModels()
    ]);
}


/* =========================================================
   DOM READY
   ========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    initializeApp
);
