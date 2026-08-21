/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.kingthorin.zap.gof.config;

import java.util.List;
import org.parosproxy.paros.common.AbstractParam;

public class GofParam extends AbstractParam {

    private List<String> backupExtensions = List.of("bak", "backup", "old", "orig", "tmp", "swp");
    private List<String> switchExtensions =
            List.of("php", "php3", "asp", "aspx", "jsp", "jspx", "py", "rb", "pl");
    private List<String> filenameSuffixes =
            List.of("~", ".bak", ".backup", ".old", ".orig", ".tmp", ".swp");
    private List<String> filenamePrefixes = List.of(".", "_", "~");
    private List<String> directorySuffixes =
            List.of("bak", "backup", "old", "orig", "_old", "_backup");
    private List<String> directoryPrefixes = List.of(".", "_", "~");
    private List<String> customBackupExtensions = List.of();
    private List<String> customFilenameSuffixes = List.of();
    private List<String> customDirectorySuffixes = List.of();
    private boolean extensionAppendEnabled = true;
    private boolean extensionReplaceEnabled = true;
    private boolean extensionSwitchEnabled = true;
    private boolean filenameSuffixEnabled = true;
    private boolean filenamePrefixEnabled = true;
    private boolean directorySuffixEnabled = true;
    private boolean directoryPrefixEnabled = true;

    public GofParam() {}

    @Override
    protected void parse() {}

    public List<String> getEffectiveBackupExtensions() {
        return backupExtensions;
    }

    public void setBackupExtensions(List<String> extensions) {
        this.backupExtensions = extensions;
    }

    public List<String> getEffectiveSwitchExtensions() {
        return switchExtensions;
    }

    public void setSwitchExtensions(List<String> extensions) {
        this.switchExtensions = extensions;
    }

    public List<String> getEffectiveFilenameSuffixes() {
        return filenameSuffixes;
    }

    public void setFilenameSuffixes(List<String> suffixes) {
        this.filenameSuffixes = suffixes;
    }

    public List<String> getEffectiveFilenamePrefixes() {
        return filenamePrefixes;
    }

    public void setFilenamePrefixes(List<String> prefixes) {
        this.filenamePrefixes = prefixes;
    }

    public List<String> getEffectiveDirectorySuffixes() {
        return directorySuffixes;
    }

    public void setDirectorySuffixes(List<String> suffixes) {
        this.directorySuffixes = suffixes;
    }

    public List<String> getEffectiveDirectoryPrefixes() {
        return directoryPrefixes;
    }

    public void setDirectoryPrefixes(List<String> prefixes) {
        this.directoryPrefixes = prefixes;
    }

    public List<String> getCustomBackupExtensions() {
        return customBackupExtensions;
    }

    public void setCustomBackupExtensions(List<String> extensions) {
        this.customBackupExtensions = extensions;
    }

    public List<String> getCustomFilenameSuffixes() {
        return customFilenameSuffixes;
    }

    public void setCustomFilenameSuffixes(List<String> suffixes) {
        this.customFilenameSuffixes = suffixes;
    }

    public List<String> getCustomDirectorySuffixes() {
        return customDirectorySuffixes;
    }

    public void setCustomDirectorySuffixes(List<String> suffixes) {
        this.customDirectorySuffixes = suffixes;
    }

    public boolean isExtensionAppendEnabled() {
        return extensionAppendEnabled;
    }

    public void setExtensionAppendEnabled(boolean enabled) {
        this.extensionAppendEnabled = enabled;
    }

    public boolean isExtensionReplaceEnabled() {
        return extensionReplaceEnabled;
    }

    public void setExtensionReplaceEnabled(boolean enabled) {
        this.extensionReplaceEnabled = enabled;
    }

    public boolean isExtensionSwitchEnabled() {
        return extensionSwitchEnabled;
    }

    public void setExtensionSwitchEnabled(boolean enabled) {
        this.extensionSwitchEnabled = enabled;
    }

    public boolean isFilenameSuffixEnabled() {
        return filenameSuffixEnabled;
    }

    public void setFilenameSuffixEnabled(boolean enabled) {
        this.filenameSuffixEnabled = enabled;
    }

    public boolean isFilenamePrefixEnabled() {
        return filenamePrefixEnabled;
    }

    public void setFilenamePrefixEnabled(boolean enabled) {
        this.filenamePrefixEnabled = enabled;
    }

    public boolean isDirectorySuffixEnabled() {
        return directorySuffixEnabled;
    }

    public void setDirectorySuffixEnabled(boolean enabled) {
        this.directorySuffixEnabled = enabled;
    }

    public boolean isDirectoryPrefixEnabled() {
        return directoryPrefixEnabled;
    }

    public void setDirectoryPrefixEnabled(boolean enabled) {
        this.directoryPrefixEnabled = enabled;
    }
}
