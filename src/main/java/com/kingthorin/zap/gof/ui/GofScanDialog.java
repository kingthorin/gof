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
package com.kingthorin.zap.gof.ui;

import com.kingthorin.zap.gof.config.GofOptionsPanel;
import com.kingthorin.zap.gof.config.GofParam;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;

/**
 * Per-invocation scan dialog.
 *
 * <p>Only exposes attack strength, since it is the only {@link GofParam} setting that reliably
 * propagates through the (unmodified) core active scan engine to the running plugin instance.
 * Strategy toggles and custom wordlists are configured via Tools &rarr; Options &rarr; Good Old
 * Files instead.
 */
@SuppressWarnings("serial")
public class GofScanDialog extends JDialog {

    /**
     * Strength chosen by the user in a previous invocation of this dialog, within the current ZAP
     * session only. {@code null} until the user picks something, so the dialog initially reflects
     * the saved Options default.
     */
    private static AttackStrength lastUsedStrength = null;

    private GofParam result = null;

    @SuppressWarnings("this-escape")
    public GofScanDialog(Component parent) {
        super(
                parent != null
                        ? SwingUtilities.getWindowAncestor(parent)
                        : View.getSingleton().getMainFrame(),
                "Good Old Files Scan Options",
                ModalityType.APPLICATION_MODAL);

        var optionsParam = Model.getSingleton().getOptionsParam();
        GofParam gofParam = optionsParam.getParamSet(GofParam.class);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(5, 5));

        JPanel strengthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JLabel strengthLabel = new JLabel("Attack Strength:");
        JComboBox<String> strengthCombo = new JComboBox<>(GofOptionsPanel.attackStrengthLabels());
        AttackStrength initialStrength =
                lastUsedStrength != null
                        ? lastUsedStrength
                        : AttackStrength.valueOf(gofParam.getAttackStrength());
        strengthCombo.setSelectedItem(GofOptionsPanel.attackStrengthLabel(initialStrength));
        strengthPanel.add(strengthLabel);
        strengthPanel.add(strengthCombo);
        add(strengthPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        JButton okBtn = new JButton("OK");
        JButton cancelBtn = new JButton("Cancel");

        okBtn.addActionListener(
                e -> {
                    AttackStrength selected =
                            GofOptionsPanel.SELECTABLE_STRENGTHS[strengthCombo.getSelectedIndex()];
                    lastUsedStrength = selected;
                    result = (GofParam) gofParam.clone();
                    result.setAttackStrength(selected.name());
                    dispose();
                });

        cancelBtn.addActionListener(e -> dispose());

        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        getRootPane().setDefaultButton(okBtn);

        pack();
        setLocationRelativeTo(parent);
    }

    public static GofParam showDialog(Component parent) {
        GofScanDialog dialog = new GofScanDialog(parent);
        dialog.setVisible(true);
        return dialog.result;
    }
}
