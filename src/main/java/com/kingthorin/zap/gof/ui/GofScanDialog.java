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
import java.awt.FlowLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import org.parosproxy.paros.model.Model;

@SuppressWarnings("serial")
public class GofScanDialog extends JDialog {

    private GofOptionsPanel panel;
    private GofParam result = null;

    @SuppressWarnings("this-escape")
    public GofScanDialog(java.awt.Component parent) {
        super(
                javax.swing.SwingUtilities.getWindowAncestor(parent),
                "Good Old Files Scan Options",
                ModalityType.APPLICATION_MODAL);

        var optionsParam = Model.getSingleton().getOptionsParam();
        panel = new GofOptionsPanel();
        panel.initParam(optionsParam);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(5, 5));
        add(panel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        JButton resetBtn = new JButton("Reset");
        JButton setDefaultsBtn = new JButton("Set as Defaults");
        JButton okBtn = new JButton("OK");
        JButton cancelBtn = new JButton("Cancel");

        resetBtn.addActionListener(
                e -> {
                    panel.initParam(optionsParam);
                });

        setDefaultsBtn.addActionListener(
                e -> {
                    try {
                        panel.saveParam(optionsParam);
                    } catch (Exception ex) {
                        // Silent ignore
                    }
                });

        okBtn.addActionListener(
                e -> {
                    try {
                        var tempParam = new org.parosproxy.paros.model.OptionsParam();
                        panel.saveParam(tempParam);
                        result = tempParam.getParamSet(GofParam.class);
                    } catch (Exception ex) {
                        result = optionsParam.getParamSet(GofParam.class);
                    }
                    dispose();
                });

        cancelBtn.addActionListener(e -> dispose());

        buttonPanel.add(resetBtn);
        buttonPanel.add(setDefaultsBtn);
        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(parent);
    }

    public static GofParam showDialog(java.awt.Component parent) {
        GofScanDialog dialog = new GofScanDialog(parent);
        dialog.setVisible(true);
        return dialog.result;
    }
}
