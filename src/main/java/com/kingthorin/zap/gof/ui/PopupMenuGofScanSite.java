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

import com.kingthorin.zap.gof.ascan.GofScanLauncher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.commonlib.MenuWeights;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemSiteNodeContainer;

public class PopupMenuGofScanSite extends PopupMenuItemSiteNodeContainer {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(PopupMenuGofScanSite.class);

    public PopupMenuGofScanSite() {
        super(Constant.messages.getString("gof.ui.popup.site"));
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("attack.site.popup");
    }

    @Override
    public int getParentWeight() {
        return MenuWeights.MENU_ATTACK_WEIGHT;
    }

    @Override
    public void performAction(SiteNode node) {
        try {
            var config = GofScanDialog.showDialog(null);
            if (config != null) {
                GofScanLauncher.scan(node, true, config);
            }
        } catch (Exception e) {
            LOGGER.error("Error launching GoF scan from menu: {}", e.getMessage(), e);
        }
    }

    @Override
    public boolean isButtonEnabledForSiteNode(SiteNode node) {
        return !node.isRoot();
    }

    @Override
    protected boolean isEnableForInvoker(
            Invoker invoker, HttpMessageContainer httpMessageContainer) {
        return invoker == Invoker.SITES_PANEL || invoker == Invoker.HISTORY_PANEL;
    }
}
