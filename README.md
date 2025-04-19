# Network Anomaly Detector GUI

A Java Swing desktop application for monitoring Windows Event Logs (Application, Security, System, Setup) to help identify potential security anomalies and system issues through filtering and highlighting.

---

**Table of Contents**

*   [Overview](#overview)
*   [Features](#features)
*   [Screenshots](#screenshots)
*   [Prerequisites](#prerequisites)
*   [Installation & Setup](#installation--setup)
*   [Usage Guide](#usage-guide)
*   [Technology Stack](#technology-stack)
*   [Limitations & Known Issues](#limitations--known-issues)
*   [Future Enhancements](#future-enhancements)
*   [Contributing](#contributing)
*   [License](#license)
*   [Contact](#contact)

---

## Overview

The Network Anomaly Detector GUI provides a user-friendly interface to tackle the overwhelming volume of Windows Event Logs. Instead of manually sifting through logs or relying solely on complex PowerShell commands, this tool allows users to:

1.  Fetch recent events from multiple key Windows logs.
2.  View logs chronologically (newest first).
3.  Automatically highlight potential anomalies (based on Event ID/Level) using distinct colors.
4.  Filter logs effectively by Log Name, detected Anomaly Type, and free-text search.
5.  Navigate large result sets easily using pagination.

It leverages PowerShell's `Get-WinEvent` cmdlet in the background for native log access and presents the information within a Java Swing GUI.

## Features

*   **Multi-Log Fetching:** Retrieves events from Application, Security, System, and Setup logs.
*   **Anomaly Detection:** Identifies potential anomalies based on predefined Event IDs and Levels (Critical, Error, Warning). Includes rules for:
    *   Failed Logons (4625)
    *   Account Lockouts (4740)
    *   Audit Log Cleared (1102)
    *   User/Group Management Changes
    *   Service Crashes & Unexpected Shutdowns
    *   And more... (See Event Info feature)
*   **Color-Coded Highlighting:** Visually distinguishes different types of anomalies and search results.
*   **Comprehensive Filtering:**
    *   Filter by specific **Log Name**.
    *   Filter by **Anomaly Type** (Show All, All Anomalies, Specific Type).
    *   Case-insensitive **Text Search**.
*   **Chronological Display & Pagination:** Shows logs newest-first and handles large results with page navigation (100 entries/page).
*   **Event ID Information:** Built-in dialog explaining common Event IDs and their significance, with corresponding severity colors.
*   **Log Export:** Save the currently visible page of logs to a `.txt` file.
*   **Auto-Refresh:** Optionally refresh logs automatically at configurable intervals (30s, 1m, 2m, 5m).
*   **Reset View:** Button to clear all filters and fetch fresh logs.

## Screenshots

**Main Window:**
![Main application interface showing log pane, filters, and controls.](https://github.com/surajmapari/NetworkAnomalyDetectorGUI/blob/main/images/Screenshot%202025-04-19%20114950.png)

**Filtering in Action:**
![Application showing filters applied (e.g., Log Name=Security, Anomaly Type=Failed Login).](https://github.com/surajmapari/NetworkAnomalyDetectorGUI/blob/main/images/Screenshot%202025-04-19%20115255.png)

**Event Info Dialog:**
![The Event Info dialog box showing descriptions and colors for various Event IDs.](https://github.com/surajmapari/NetworkAnomalyDetectorGUI/blob/main/images/Screenshot%202025-04-19%20115420.png)

## Prerequisites

*   **Operating System:** Windows (Tested on Windows 10/11, should work on Server versions)
*   **Java:** Java Runtime Environment (JRE) or Development Kit (JDK) **Version 11 or higher** installed and configured in your system's PATH.
*   **PowerShell:** PowerShell version 5.1 or later (usually included with modern Windows) must be available.
*   **Administrator Privileges:** **Crucially, the application MUST be run "As Administrator"** to access the Security Event Log and potentially other system logs.

## Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/<YourUsername>/<YourRepoName>.git
    cd <YourRepoName>
    ```

2.  **Compile (If necessary):**
    *   **Using an IDE (Recommended):** Open the project in an IDE like IntelliJ IDEA, Eclipse, or VS Code with Java extensions. Build the project using the IDE's build command (this usually handles dependencies and classpath).
    *   **Using Command Line (Manual):** Navigate to the source directory (e.g., `src`) and compile the `.java` file:
        ```bash
        # Adjust path separators (\ or /) based on your shell
        # Make sure your JDK's bin directory is in your PATH
        javac NetworkAnomalyDetectorGUI.java
        # This will create NetworkAnomalyDetectorGUI.class and inner class files
        ```
    *   **(Optional) Create JAR:** You can package the compiled classes into an executable JAR file (consult IDE documentation or `jar` command specifics).

3.  **Run the Application:**
    *   **From IDE:** Find the `NetworkAnomalyDetectorGUI` class and run its `main` method. **Remember to configure your IDE to launch the application with Administrator privileges if possible, or restart your IDE itself "As Administrator" before running.**
    *   **From Command Line (if compiled manually):** Navigate to the directory containing the `.class` files (likely the `src` or a `bin`/`out` directory) and run:
        ```bash
        # !! RUN THIS COMMAND PROMPT/TERMINAL 'AS ADMINISTRATOR' !!
        java NetworkAnomalyDetectorGUI
        ```
    *   **From JAR file (if created):**
        ```bash
        # !! RUN THIS COMMAND PROMPT/TERMINAL 'AS ADMINISTRATOR' !!
        java -jar YourAppName.jar
        ```

    *   **Admin Rights Reminder:** A warning dialog will appear on startup if the application likely lacks administrator rights. If you see this, close the application and relaunch it correctly "As Administrator".

## Usage Guide

1.  **Launch:** Start the application **"As Administrator"** (see Setup).
2.  **Initial Load:** Click the **"Refresh"** button to fetch initial logs. Observe the status bar and progress bar.
3.  **Filtering:**
    *   Use the **"Log Name"** dropdown to focus on specific logs (e.g., `Security`).
    *   Use the **"Anomaly Type"** dropdown to filter by severity/type (e.g., `Show All Anomalies`, `Sec: Account Lockout`).
    *   Enter keywords (username, IP, error code) into the **"Filter Text"** field.
    *   Click **"Apply Filters"** to update the view.
4.  **Review Logs:** Examine the logs in the main pane. Anomalies will be highlighted. Recent events are at the top.
5.  **Pagination:** If many logs match filters, use the **"<< Previous"** and **"Next >>"** buttons to navigate pages.
6.  **Understand Anomalies:** Click **"Event Info"** to see descriptions and severity colors for common Event IDs flagged by the tool.
7.  **Export:** Navigate to the desired page and click **"Export Visible"** to save the current page's logs to a text file.
8.  **Auto-Refresh:** Check the **"Auto Refresh"** box and select an interval to have logs update automatically. Uncheck to stop.
9.  **Reset:** Click **"Reset All & Refresh"** to clear all filters and reload fresh logs from the system.

## Technology Stack

*   **Core:** Java SE 11+
*   **UI:** Java Swing (Nimbus Look and Feel)
*   **System Interaction:** PowerShell (`Get-WinEvent`) invoked via `java.lang.ProcessBuilder`
*   **Parsing:** Java Regular Expressions (`java.util.regex`)

## Limitations & Known Issues

*   **Administrator Privileges:** Mandatory for full functionality (especially Security logs).
*   **PowerShell Dependency:** Performance relies on the system's PowerShell execution speed. Requires PowerShell to be installed and runnable.
*   **Parsing Fragility:** Relies on specific PowerShell `Format-List` output. Significant changes in Windows event formatting or system locale *could* break parsing. (Future Enhancement: Use JSON).
*   **Scalability:** In-memory storage limits analysis to the number of events fetched per refresh (`MAX_EVENTS_TO_FETCH`). Not designed for analyzing months/years of historical logs simultaneously.
*   **Simple Detection:** Anomaly detection uses predefined rules based on Event ID/Level. It does not perform advanced correlation, statistical baselining, or machine learning.
*   **No Persistence:** All fetched data and filter settings are lost when the application is closed.

## Future Enhancements

*   **JSON Parsing:** Refactor to use `ConvertTo-Json` in PowerShell and a Java JSON library (Gson/Jackson) for robust parsing.
*   **Event Correlation:** Add basic rules to link related events (e.g., multiple 4625 -> 4624).
*   **Database Backend:** Use SQLite (or similar) to store logs persistently for historical analysis and better scalability.
*   **Whitelisting:** Allow users to define rules to ignore specific known benign events.
*   **GeoIP Lookup:** Add geographic context to external IP addresses.
*   **Detailed Event View:** Show the *full* raw log details for a selected entry.
*   **UI Improvements:** Customizable highlighting, savable filters, advanced log source selection.
*   **Configuration File:** Externalize settings like `MAX_EVENTS_TO_FETCH`.

## Contributing

Contributions are welcome! If you'd like to contribute, please follow these general steps:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix (`git checkout -b feature/your-feature-name`).
3.  Make your changes and commit them (`git commit -m 'Add some feature'`).
4.  Push your changes to your branch (`git push origin feature/your-feature-name`).
5.  Open a Pull Request against the `main` branch of this repository.

Please open an issue first to discuss significant changes or new features.

## License

This project is licensed under the **[MIT License](LICENSE)**. <!-- Choose your license and add a LICENSE file -->
