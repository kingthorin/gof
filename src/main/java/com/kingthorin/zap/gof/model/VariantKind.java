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
package com.kingthorin.zap.gof.model;

import org.parosproxy.paros.Constant;

public enum VariantKind {
    EXTENSION_APPEND("gof.variant.extension.append"),
    EXTENSION_REPLACE("gof.variant.extension.replace"),
    EXTENSION_SWITCH("gof.variant.extension.switch"),
    EXTENSION_COMBINATION("gof.variant.extension.combination"),
    FILENAME_SUFFIX("gof.variant.filename.suffix"),
    FILENAME_PREFIX("gof.variant.filename.prefix"),
    DIGIT_ENUMERATION("gof.variant.digit.enumeration"),
    DIRECTORY_SUFFIX("gof.variant.directory.suffix"),
    DIRECTORY_PREFIX("gof.variant.directory.prefix");

    private final String messageKey;

    VariantKind(String messageKey) {
        this.messageKey = messageKey;
    }

    public String getLabel() {
        return Constant.messages.getString(messageKey);
    }
}
