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
package com.kingthorin.zap.gof.config;

import java.util.ArrayList;
import java.util.List;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class GofParam extends VersionedAbstractParam {

    private static final int CURRENT_CONFIG_VERSION = 1;
    private static final String GOF_BASE_KEY = "gof";
    private static final String CONFIG_VERSION_KEY = GOF_BASE_KEY + VERSION_ATTRIBUTE;

    private static final String BACKUP_EXTENSIONS_KEY = GOF_BASE_KEY + ".backupExtensions";
    private static final String SWITCH_EXTENSIONS_KEY = GOF_BASE_KEY + ".switchExtensions";
    private static final String FILENAME_SUFFIXES_KEY = GOF_BASE_KEY + ".filenameSuffixes";
    private static final String FILENAME_PREFIXES_KEY = GOF_BASE_KEY + ".filenamePrefixes";
    private static final String DIRECTORY_SUFFIXES_KEY = GOF_BASE_KEY + ".directorySuffixes";
    private static final String DIRECTORY_PREFIXES_KEY = GOF_BASE_KEY + ".directoryPrefixes";

    private static final String EXTENSION_APPEND_ENABLED_KEY =
            GOF_BASE_KEY + ".extensionAppendEnabled";
    private static final String EXTENSION_REPLACE_ENABLED_KEY =
            GOF_BASE_KEY + ".extensionReplaceEnabled";
    private static final String EXTENSION_SWITCH_ENABLED_KEY =
            GOF_BASE_KEY + ".extensionSwitchEnabled";
    private static final String EXTENSION_COMBINATION_ENABLED_KEY =
            GOF_BASE_KEY + ".extensionCombinationEnabled";
    private static final String FILENAME_SUFFIX_ENABLED_KEY =
            GOF_BASE_KEY + ".filenameSuffixEnabled";
    private static final String FILENAME_PREFIX_ENABLED_KEY =
            GOF_BASE_KEY + ".filenamePrefixEnabled";
    private static final String DIGIT_ENUMERATION_ENABLED_KEY =
            GOF_BASE_KEY + ".digitEnumerationEnabled";
    private static final String DIRECTORY_SUFFIX_ENABLED_KEY =
            GOF_BASE_KEY + ".directorySuffixEnabled";
    private static final String DIRECTORY_PREFIX_ENABLED_KEY =
            GOF_BASE_KEY + ".directoryPrefixEnabled";
    private static final String ATTACK_STRENGTH_KEY = GOF_BASE_KEY + ".attackStrength";

    private List<String> backupExtensions =
            List.of(
                    "old", "conf", "1", "2", "12", "123", "txt", "bac", "bak", "backup", "asd",
                    "dsa", "a", "aa", "aaa", "tar.gz", "tar", "7z", "zip", "inc", "~");
    private List<String> switchExtensions =
            List.of("php", "php3", "asp", "aspx", "jsp", "jspx", "py", "rb", "pl");
    private List<String> filenameSuffixes = List.of(" - Copy", "_old");
    private List<String> filenamePrefixes = List.of("Copy of", "old_", "Old_");
    private List<String> directorySuffixes =
            List.of("bak", "backup", "old", "orig", "_old", "_backup");
    private List<String> directoryPrefixes = List.of(".", "_", "~");
    private List<String> customBackupExtensions = List.of();
    private List<String> customFilenameSuffixes = List.of();
    private List<String> customDirectorySuffixes = List.of();
    private boolean extensionAppendEnabled = true;
    private boolean extensionReplaceEnabled = true;
    private boolean extensionSwitchEnabled = true;
    private boolean extensionCombinationEnabled = true;
    private boolean filenameSuffixEnabled = true;
    private boolean filenamePrefixEnabled = true;
    private boolean digitEnumerationEnabled = true;
    private boolean directorySuffixEnabled = true;
    private boolean directoryPrefixEnabled = true;
    private String attackStrength = "MEDIUM";

    public GofParam() {}

    private List<String> loadList(String key, List<String> current) {
        List<?> values = getConfig().getList(key);
        if (values == null || values.isEmpty()) {
            return current;
        }
        return new ArrayList<>(values.stream().map(Object::toString).toList());
    }

    @Override
    protected void parseImpl() {
        backupExtensions = loadList(BACKUP_EXTENSIONS_KEY, backupExtensions);
        switchExtensions = loadList(SWITCH_EXTENSIONS_KEY, switchExtensions);
        filenameSuffixes = loadList(FILENAME_SUFFIXES_KEY, filenameSuffixes);
        filenamePrefixes = loadList(FILENAME_PREFIXES_KEY, filenamePrefixes);
        directorySuffixes = loadList(DIRECTORY_SUFFIXES_KEY, directorySuffixes);
        directoryPrefixes = loadList(DIRECTORY_PREFIXES_KEY, directoryPrefixes);
        customBackupExtensions =
                loadList(GOF_BASE_KEY + ".customBackupExtensions", customBackupExtensions);
        customFilenameSuffixes =
                loadList(GOF_BASE_KEY + ".customFilenameSuffixes", customFilenameSuffixes);
        customDirectorySuffixes =
                loadList(GOF_BASE_KEY + ".customDirectorySuffixes", customDirectorySuffixes);

        extensionAppendEnabled = getBoolean(EXTENSION_APPEND_ENABLED_KEY, extensionAppendEnabled);
        extensionReplaceEnabled =
                getBoolean(EXTENSION_REPLACE_ENABLED_KEY, extensionReplaceEnabled);
        extensionSwitchEnabled = getBoolean(EXTENSION_SWITCH_ENABLED_KEY, extensionSwitchEnabled);
        extensionCombinationEnabled =
                getBoolean(EXTENSION_COMBINATION_ENABLED_KEY, extensionCombinationEnabled);
        filenameSuffixEnabled = getBoolean(FILENAME_SUFFIX_ENABLED_KEY, filenameSuffixEnabled);
        filenamePrefixEnabled = getBoolean(FILENAME_PREFIX_ENABLED_KEY, filenamePrefixEnabled);
        digitEnumerationEnabled =
                getBoolean(DIGIT_ENUMERATION_ENABLED_KEY, digitEnumerationEnabled);
        directorySuffixEnabled = getBoolean(DIRECTORY_SUFFIX_ENABLED_KEY, directorySuffixEnabled);
        directoryPrefixEnabled = getBoolean(DIRECTORY_PREFIX_ENABLED_KEY, directoryPrefixEnabled);

        attackStrength = getString(ATTACK_STRENGTH_KEY, "MEDIUM");
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // No migrations for v1
    }

    public List<String> getEffectiveBackupExtensions() {
        return backupExtensions;
    }

    public void setBackupExtensions(List<String> extensions) {
        this.backupExtensions = extensions;
        getConfig().setProperty(BACKUP_EXTENSIONS_KEY, extensions);
    }

    public List<String> getEffectiveSwitchExtensions() {
        return switchExtensions;
    }

    public void setSwitchExtensions(List<String> extensions) {
        this.switchExtensions = extensions;
        getConfig().setProperty(SWITCH_EXTENSIONS_KEY, extensions);
    }

    public List<String> getEffectiveFilenameSuffixes() {
        return filenameSuffixes;
    }

    public void setFilenameSuffixes(List<String> suffixes) {
        this.filenameSuffixes = suffixes;
        getConfig().setProperty(FILENAME_SUFFIXES_KEY, suffixes);
    }

    public List<String> getEffectiveFilenamePrefixes() {
        return filenamePrefixes;
    }

    public void setFilenamePrefixes(List<String> prefixes) {
        this.filenamePrefixes = prefixes;
        getConfig().setProperty(FILENAME_PREFIXES_KEY, prefixes);
    }

    public List<String> getEffectiveDirectorySuffixes() {
        return directorySuffixes;
    }

    public void setDirectorySuffixes(List<String> suffixes) {
        this.directorySuffixes = suffixes;
        getConfig().setProperty(DIRECTORY_SUFFIXES_KEY, suffixes);
    }

    public List<String> getEffectiveDirectoryPrefixes() {
        return directoryPrefixes;
    }

    public void setDirectoryPrefixes(List<String> prefixes) {
        this.directoryPrefixes = prefixes;
        getConfig().setProperty(DIRECTORY_PREFIXES_KEY, prefixes);
    }

    public List<String> getCustomBackupExtensions() {
        return customBackupExtensions;
    }

    public void setCustomBackupExtensions(List<String> extensions) {
        this.customBackupExtensions = extensions;
        getConfig().setProperty(GOF_BASE_KEY + ".customBackupExtensions", extensions);
    }

    public List<String> getCustomFilenameSuffixes() {
        return customFilenameSuffixes;
    }

    public void setCustomFilenameSuffixes(List<String> suffixes) {
        this.customFilenameSuffixes = suffixes;
        getConfig().setProperty(GOF_BASE_KEY + ".customFilenameSuffixes", suffixes);
    }

    public List<String> getCustomDirectorySuffixes() {
        return customDirectorySuffixes;
    }

    public void setCustomDirectorySuffixes(List<String> suffixes) {
        this.customDirectorySuffixes = suffixes;
        getConfig().setProperty(GOF_BASE_KEY + ".customDirectorySuffixes", suffixes);
    }

    public boolean isExtensionAppendEnabled() {
        return extensionAppendEnabled;
    }

    public void setExtensionAppendEnabled(boolean enabled) {
        this.extensionAppendEnabled = enabled;
        getConfig().setProperty(EXTENSION_APPEND_ENABLED_KEY, enabled);
    }

    public boolean isExtensionReplaceEnabled() {
        return extensionReplaceEnabled;
    }

    public void setExtensionReplaceEnabled(boolean enabled) {
        this.extensionReplaceEnabled = enabled;
        getConfig().setProperty(EXTENSION_REPLACE_ENABLED_KEY, enabled);
    }

    public boolean isExtensionSwitchEnabled() {
        return extensionSwitchEnabled;
    }

    public void setExtensionSwitchEnabled(boolean enabled) {
        this.extensionSwitchEnabled = enabled;
        getConfig().setProperty(EXTENSION_SWITCH_ENABLED_KEY, enabled);
    }

    public boolean isExtensionCombinationEnabled() {
        return extensionCombinationEnabled;
    }

    public void setExtensionCombinationEnabled(boolean enabled) {
        this.extensionCombinationEnabled = enabled;
        getConfig().setProperty(EXTENSION_COMBINATION_ENABLED_KEY, enabled);
    }

    public boolean isFilenameSuffixEnabled() {
        return filenameSuffixEnabled;
    }

    public void setFilenameSuffixEnabled(boolean enabled) {
        this.filenameSuffixEnabled = enabled;
        getConfig().setProperty(FILENAME_SUFFIX_ENABLED_KEY, enabled);
    }

    public boolean isFilenamePrefixEnabled() {
        return filenamePrefixEnabled;
    }

    public void setFilenamePrefixEnabled(boolean enabled) {
        this.filenamePrefixEnabled = enabled;
        getConfig().setProperty(FILENAME_PREFIX_ENABLED_KEY, enabled);
    }

    public boolean isDigitEnumerationEnabled() {
        return digitEnumerationEnabled;
    }

    public void setDigitEnumerationEnabled(boolean enabled) {
        this.digitEnumerationEnabled = enabled;
        getConfig().setProperty(DIGIT_ENUMERATION_ENABLED_KEY, enabled);
    }

    public boolean isDirectorySuffixEnabled() {
        return directorySuffixEnabled;
    }

    public void setDirectorySuffixEnabled(boolean enabled) {
        this.directorySuffixEnabled = enabled;
        getConfig().setProperty(DIRECTORY_SUFFIX_ENABLED_KEY, enabled);
    }

    public boolean isDirectoryPrefixEnabled() {
        return directoryPrefixEnabled;
    }

    public void setDirectoryPrefixEnabled(boolean enabled) {
        this.directoryPrefixEnabled = enabled;
        getConfig().setProperty(DIRECTORY_PREFIX_ENABLED_KEY, enabled);
    }

    public String getAttackStrength() {
        return attackStrength;
    }

    public void setAttackStrength(String strength) {
        this.attackStrength = strength;
        getConfig().setProperty(ATTACK_STRENGTH_KEY, strength);
    }
}
