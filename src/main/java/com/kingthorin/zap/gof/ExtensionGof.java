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
package com.kingthorin.zap.gof;

import com.kingthorin.zap.gof.config.GofOptionsPanel;
import com.kingthorin.zap.gof.config.GofParam;
import com.kingthorin.zap.gof.ui.PopupMenuGofScanSite;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

public class ExtensionGof extends ExtensionAdaptor {

    public static final String NAME = "ExtensionGof";
    protected static final String PREFIX = "gof";

    public ExtensionGof() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(new GofParam());

        if (hasView()) {
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuGofScanSite());
            extensionHook.getHookView().addOptionPanel(new GofOptionsPanel());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".addOn.name");
    }
}
