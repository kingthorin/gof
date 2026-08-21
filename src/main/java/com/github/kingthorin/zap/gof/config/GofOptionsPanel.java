/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.kingthorin.zap.gof.config;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;

public class GofOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private JCheckBox extensionAppendCheckbox;
    private JCheckBox extensionReplaceCheckbox;
    private JCheckBox extensionSwitchCheckbox;
    private JCheckBox filenameSuffixCheckbox;
    private JCheckBox filenamePrefixCheckbox;
    private JCheckBox directorySuffixCheckbox;
    private JCheckBox directoryPrefixCheckbox;
    private JTextArea customBackupExtensionsArea;
    private JTextArea customFilenameSuffixesArea;
    private JTextArea customDirectorySuffixesArea;

    @SuppressWarnings("this-escape")
    public GofOptionsPanel() {
        super();
        initUI();
        setName("Good Old Files");
    }

    private void initUI() {
        this.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new java.awt.Insets(5, 5, 5, 5);

        this.add(new JLabel("Permutation Strategies:"), gbc);
        gbc.gridy++;

        extensionAppendCheckbox = new JCheckBox("Extension Append (file.php → file.php.bak)");
        this.add(extensionAppendCheckbox, gbc);
        gbc.gridy++;

        extensionReplaceCheckbox = new JCheckBox("Extension Replace (file.php → file.bak)");
        this.add(extensionReplaceCheckbox, gbc);
        gbc.gridy++;

        extensionSwitchCheckbox = new JCheckBox("Extension Switch (file.php → file.asp)");
        this.add(extensionSwitchCheckbox, gbc);
        gbc.gridy++;

        filenameSuffixCheckbox = new JCheckBox("Filename Suffix (file.php → file.old.php)");
        this.add(filenameSuffixCheckbox, gbc);
        gbc.gridy++;

        filenamePrefixCheckbox = new JCheckBox("Filename Prefix (file.php → .file.php)");
        this.add(filenamePrefixCheckbox, gbc);
        gbc.gridy++;

        directorySuffixCheckbox = new JCheckBox("Directory Suffix (/admin/ → /admin_old/)");
        this.add(directorySuffixCheckbox, gbc);
        gbc.gridy++;

        directoryPrefixCheckbox = new JCheckBox("Directory Prefix (/admin/ → /_admin/)");
        this.add(directoryPrefixCheckbox, gbc);
        gbc.gridy++;

        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.add(new JLabel("Custom Backup Extensions (one per line):"), gbc);
        gbc.gridy++;
        gbc.weighty = 0.3;
        gbc.fill = GridBagConstraints.BOTH;
        customBackupExtensionsArea = new JTextArea(3, 40);
        customBackupExtensionsArea.setLineWrap(true);
        this.add(new JScrollPane(customBackupExtensionsArea), gbc);

        gbc.gridy++;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.add(new JLabel("Custom Filename Suffixes (one per line):"), gbc);
        gbc.gridy++;
        gbc.weighty = 0.3;
        gbc.fill = GridBagConstraints.BOTH;
        customFilenameSuffixesArea = new JTextArea(3, 40);
        customFilenameSuffixesArea.setLineWrap(true);
        this.add(new JScrollPane(customFilenameSuffixesArea), gbc);

        gbc.gridy++;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.add(new JLabel("Custom Directory Suffixes (one per line):"), gbc);
        gbc.gridy++;
        gbc.weighty = 0.4;
        gbc.fill = GridBagConstraints.BOTH;
        customDirectorySuffixesArea = new JTextArea(3, 40);
        customDirectorySuffixesArea.setLineWrap(true);
        this.add(new JScrollPane(customDirectorySuffixesArea), gbc);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        GofParam param = optionsParam.getParamSet(GofParam.class);
        extensionAppendCheckbox.setSelected(param.isExtensionAppendEnabled());
        extensionReplaceCheckbox.setSelected(param.isExtensionReplaceEnabled());
        extensionSwitchCheckbox.setSelected(param.isExtensionSwitchEnabled());
        filenameSuffixCheckbox.setSelected(param.isFilenameSuffixEnabled());
        filenamePrefixCheckbox.setSelected(param.isFilenamePrefixEnabled());
        directorySuffixCheckbox.setSelected(param.isDirectorySuffixEnabled());
        directoryPrefixCheckbox.setSelected(param.isDirectoryPrefixEnabled());
        customBackupExtensionsArea.setText(String.join("\n", param.getCustomBackupExtensions()));
        customFilenameSuffixesArea.setText(String.join("\n", param.getCustomFilenameSuffixes()));
        customDirectorySuffixesArea.setText(String.join("\n", param.getCustomDirectorySuffixes()));
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        GofParam param = optionsParam.getParamSet(GofParam.class);
        param.setExtensionAppendEnabled(extensionAppendCheckbox.isSelected());
        param.setExtensionReplaceEnabled(extensionReplaceCheckbox.isSelected());
        param.setExtensionSwitchEnabled(extensionSwitchCheckbox.isSelected());
        param.setFilenameSuffixEnabled(filenameSuffixCheckbox.isSelected());
        param.setFilenamePrefixEnabled(filenamePrefixCheckbox.isSelected());
        param.setDirectorySuffixEnabled(directorySuffixCheckbox.isSelected());
        param.setDirectoryPrefixEnabled(directoryPrefixCheckbox.isSelected());
        param.setCustomBackupExtensions(parseTextArea(customBackupExtensionsArea));
        param.setCustomFilenameSuffixes(parseTextArea(customFilenameSuffixesArea));
        param.setCustomDirectorySuffixes(parseTextArea(customDirectorySuffixesArea));
    }

    private List<String> parseTextArea(JTextArea area) {
        List<String> list = new ArrayList<>();
        String text = area.getText().trim();
        if (!text.isEmpty()) {
            for (String line : text.split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    list.add(trimmed);
                }
            }
        }
        return list;
    }

    @Override
    public String getHelpIndex() {
        return "gof.options";
    }
}
