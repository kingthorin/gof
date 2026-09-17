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
package com.kingthorin.zap.gof.config;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;

public class GofOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    public static final AttackStrength[] SELECTABLE_STRENGTHS = {
        AttackStrength.LOW, AttackStrength.MEDIUM, AttackStrength.HIGH, AttackStrength.INSANE
    };

    private JCheckBox extensionAppendCheckbox;
    private JCheckBox extensionReplaceCheckbox;
    private JCheckBox extensionSwitchCheckbox;
    private JCheckBox extensionCombinationCheckbox;
    private JCheckBox filenameSuffixCheckbox;
    private JCheckBox filenamePrefixCheckbox;
    private JCheckBox digitEnumerationCheckbox;
    private JCheckBox directorySuffixCheckbox;
    private JCheckBox directoryPrefixCheckbox;
    private JComboBox<String> attackStrengthCombo;
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
        JPanel content = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        content.add(new JLabel("Permutation Strategies:"), gbc);
        gbc.gridy++;

        extensionAppendCheckbox = new JCheckBox("Extension Append (file.php → file.php.bak)");
        content.add(extensionAppendCheckbox, gbc);
        gbc.gridy++;

        extensionReplaceCheckbox = new JCheckBox("Extension Replace (file.php → file.bak)");
        content.add(extensionReplaceCheckbox, gbc);
        gbc.gridy++;

        extensionSwitchCheckbox = new JCheckBox("Extension Switch (file.php → file.asp)");
        content.add(extensionSwitchCheckbox, gbc);
        gbc.gridy++;

        extensionCombinationCheckbox =
                new JCheckBox("Extension Combination (file.php → file.php_old.php)");
        content.add(extensionCombinationCheckbox, gbc);
        gbc.gridy++;

        filenameSuffixCheckbox = new JCheckBox("Filename Suffix (file.php → file.old.php)");
        content.add(filenameSuffixCheckbox, gbc);
        gbc.gridy++;

        filenamePrefixCheckbox = new JCheckBox("Filename Prefix (file.php → .file.php)");
        content.add(filenamePrefixCheckbox, gbc);
        gbc.gridy++;

        digitEnumerationCheckbox =
                new JCheckBox("Digit Enumeration (file1.php → file2.php, file3.php, ...)");
        content.add(digitEnumerationCheckbox, gbc);
        gbc.gridy++;

        directorySuffixCheckbox = new JCheckBox("Directory Suffix (/admin/ → /admin_old/)");
        content.add(directorySuffixCheckbox, gbc);
        gbc.gridy++;

        directoryPrefixCheckbox = new JCheckBox("Directory Prefix (/admin/ → /_admin/)");
        content.add(directoryPrefixCheckbox, gbc);
        gbc.gridy++;

        content.add(new JLabel(Constant.messages.getString("ascan.options.strength.label")), gbc);
        gbc.gridy++;
        attackStrengthCombo = new JComboBox<>(attackStrengthLabels());
        content.add(attackStrengthCombo, gbc);
        gbc.gridy++;

        content.add(new JLabel("Custom Backup Extensions (one per line):"), gbc);
        gbc.gridy++;
        customBackupExtensionsArea = new JTextArea(5, 40);
        customBackupExtensionsArea.setLineWrap(true);
        content.add(new JScrollPane(customBackupExtensionsArea), gbc);
        gbc.gridy++;

        content.add(new JLabel("Custom Filename Suffixes (one per line):"), gbc);
        gbc.gridy++;
        customFilenameSuffixesArea = new JTextArea(5, 40);
        customFilenameSuffixesArea.setLineWrap(true);
        content.add(new JScrollPane(customFilenameSuffixesArea), gbc);
        gbc.gridy++;

        content.add(new JLabel("Custom Directory Suffixes (one per line):"), gbc);
        gbc.gridy++;
        customDirectorySuffixesArea = new JTextArea(5, 40);
        customDirectorySuffixesArea.setLineWrap(true);
        content.add(new JScrollPane(customDirectorySuffixesArea), gbc);

        this.setLayout(new BorderLayout());
        this.add(new JScrollPane(content), BorderLayout.CENTER);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        GofParam param = optionsParam.getParamSet(GofParam.class);
        extensionAppendCheckbox.setSelected(param.isExtensionAppendEnabled());
        extensionReplaceCheckbox.setSelected(param.isExtensionReplaceEnabled());
        extensionSwitchCheckbox.setSelected(param.isExtensionSwitchEnabled());
        extensionCombinationCheckbox.setSelected(param.isExtensionCombinationEnabled());
        filenameSuffixCheckbox.setSelected(param.isFilenameSuffixEnabled());
        filenamePrefixCheckbox.setSelected(param.isFilenamePrefixEnabled());
        digitEnumerationCheckbox.setSelected(param.isDigitEnumerationEnabled());
        directorySuffixCheckbox.setSelected(param.isDirectorySuffixEnabled());
        directoryPrefixCheckbox.setSelected(param.isDirectoryPrefixEnabled());
        attackStrengthCombo.setSelectedItem(
                attackStrengthLabel(AttackStrength.valueOf(param.getAttackStrength())));
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
        param.setExtensionCombinationEnabled(extensionCombinationCheckbox.isSelected());
        param.setFilenameSuffixEnabled(filenameSuffixCheckbox.isSelected());
        param.setFilenamePrefixEnabled(filenamePrefixCheckbox.isSelected());
        param.setDigitEnumerationEnabled(digitEnumerationCheckbox.isSelected());
        param.setDirectorySuffixEnabled(directorySuffixCheckbox.isSelected());
        param.setDirectoryPrefixEnabled(directoryPrefixCheckbox.isSelected());
        param.setAttackStrength(
                SELECTABLE_STRENGTHS[attackStrengthCombo.getSelectedIndex()].name());
        param.setCustomBackupExtensions(parseTextArea(customBackupExtensionsArea));
        param.setCustomFilenameSuffixes(parseTextArea(customFilenameSuffixesArea));
        param.setCustomDirectorySuffixes(parseTextArea(customDirectorySuffixesArea));
    }

    public static String attackStrengthLabel(AttackStrength strength) {
        return Constant.messages.getString(
                "ascan.options.strength." + strength.name().toLowerCase(Locale.ROOT));
    }

    public static String[] attackStrengthLabels() {
        String[] labels = new String[SELECTABLE_STRENGTHS.length];
        for (int i = 0; i < SELECTABLE_STRENGTHS.length; i++) {
            labels[i] = attackStrengthLabel(SELECTABLE_STRENGTHS[i]);
        }
        return labels;
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
