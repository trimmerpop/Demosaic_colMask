# Demosaic Tool for Unity Games

A GUI tool for modifying shaders in Unity game assets to remove mosaic/censor effects. It is built using Python and UnityPy.

This tool can operate in two modes:
1.  **Normal Mode**: Directly modifies asset files (e.g., `.assets`, `.bundle`) within a folder.
2.  **APK Mode**: Extracts an `.apk` file, modifies the assets inside, and then repacks it into a new, installable `.apk` file.

<img width="1604" height="1264" alt="image" src="https://github.com/user-attachments/assets/69d803a7-abbd-4e3b-95e6-f57b8f0613eb" />


## Features

-   **Automatic Shader Detection**: Scans folders or individual asset files to find all shaders.
-   **Mosaic Shader Auto-Selection**: Automatically identifies and selects common mosaic shaders based on keywords.
-   **Shader Replacement Suggestion**: Intelligently suggests a replacement shader for a mosaic shader by finding the most likely non-mosaic version.
-   **Demosaic (colMask Edit)**: Sets the `colMask` property of selected shaders to 0, effectively disabling the mosaic effect.
-   **Shader Replacement**: Allows replacing a problematic shader with a different, working one (e.g., replacing a mosaic shader with a standard unlit shader).
-   **Environment Check for APK Mode**: Automatically checks if Java and `uber-apk-signer.jar` are available and warns the user if they are missing.
-   **Two Operating Modes**:
    -   **Normal Mode**: Works with folders containing raw asset files (`.assets`, `.bundle`, etc.).
    -   **APK Mode**: If a folder contains only `.apk` files, the tool automatically switches to APK mode, handling extraction and repacking.
-   **User-Friendly GUI**: Provides a graphical interface to view, filter, and select shaders for modification.
-   **File Backup**: Automatically creates `.bak` files for original assets before modification in Normal Mode.

## Requirements

### 1. Python
-   Python 3.6+

### 2. Python Libraries
Install the required libraries using pip:
```shell
pip install UnityPy tkinterdnd2
```

### 3. For APK Mode
-   **Java**: Java 8 (JRE or JDK) or higher must be installed and configured in your system's `PATH`. You can verify this by opening a terminal/command prompt and typing `java -version`.
-   **uber-apk-signer**:
    1.  Download the latest `uber-apk-signer.jar` from the official releases page.
    2.  Place the downloaded `.jar` file in the **same directory** as `demosaic colMask.py`.

## How to Use

1.  **Run the Script**:
    ```shell
    python "demosaic colMask.py"
    ```

2.  **Select a Folder**:
    -   **Drag and drop** a folder or a supported file (`.apk`, `.assets`, `.unity3d`, etc.) anywhere onto the program window.
    -   **Double-click** the "Path" text box to open a folder selection dialog.

3.  **Automatic Scan & Mode Detection**:
    -   Once a folder is selected, the tool automatically scans its contents.
    -   If `.assets` files are found, it operates in **Normal Mode**.
    -   If only `.apk` files are found, it switches to **APK Mode**, automatically extracts the first APK found, and scans the assets inside.

4.  **Select Shaders**:
    -   The "Available Shaders" list will be populated. Mosaic-like shaders are automatically moved to the "Selected Shaders" list.
    -   You can manually move shaders between the two lists by double-clicking them.
    -   Use the "filter" box to search for specific shaders by name.

5.  **Process Shaders**:
    -   **To Demosaic**: Ensure the desired shaders are in the "Selected Shaders" list. The default action is to edit `colMask`.
    -   **To Replace**: Right-click a shader in the "Selected Shaders" list and choose "Replace with...". A new window will appear where you can select a source shader from the "Available Shaders" list.

6.  **Start Processing**:
    -   Click the **"Start Demosaic"** button.
    -   The tool will process all shaders in the "Selected Shaders" list according to their status (`-> colMask edit 0` or `-> [Replaced Shader Name]`).

7.  **Check Results**:
    -   **Normal Mode**: The original asset files will be modified. Backup files with a `.bak` extension will be created in the same directory (if the "Backup File" option is checked).
    -   **APK Mode**: A new APK file with a `_mod.apk` suffix will be created in the same directory as the original APK. You can then install this modified APK on an Android device.

## Important Notes

-   Modifying shaders can sometimes lead to broken or invisible graphics. Always use the backup files to restore the original state if something goes wrong.
-   Some asset files may be protected or have an unsupported format, which could cause errors during scanning or saving.
-   In APK mode, the repacked APK is signed with a generic **debug key**.
