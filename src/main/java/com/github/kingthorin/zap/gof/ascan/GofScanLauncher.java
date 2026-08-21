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
package com.github.kingthorin.zap.gof.ascan;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.model.Target;

public final class GofScanLauncher {

    private static final Logger LOGGER = LogManager.getLogger(GofScanLauncher.class);

    private GofScanLauncher() {}

    public static int scan(SiteNode node, boolean recurse) {
        try {
            ExtensionActiveScan ascanExt =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionActiveScan.class);
            if (ascanExt == null) {
                LOGGER.error("ExtensionActiveScan not found");
                return -1;
            }

            ScanPolicy policy = new ScanPolicy();
            policy.getPluginFactory().setAllPluginEnabled(false);

            Plugin gof = policy.getPluginFactory().getPlugin(60300);
            if (gof == null) {
                LOGGER.error("GofActiveScanRule plugin not found");
                return -1;
            }

            gof.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
            gof.setAttackStrength(Plugin.AttackStrength.MEDIUM);

            return ascanExt.startScan(new Target(node, recurse), null, new Object[] {policy});
        } catch (Exception e) {
            LOGGER.error("Error launching GoF scan: {}", e.getMessage(), e);
            return -1;
        }
    }
}
