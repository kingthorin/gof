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
package com.kingthorin.zap.gof.ascan;

import com.kingthorin.zap.gof.config.GofParam;
import com.kingthorin.zap.gof.model.FileNameCandidate;
import com.kingthorin.zap.gof.model.VariantKind;
import com.kingthorin.zap.gof.strategy.CandidateGenerator;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

public class GofActiveScanRule extends AbstractAppPlugin {

    private static final int PLUGIN_ID = 60300;
    private static final String PREFIX = "gof.ascan.gof";
    private static final Logger LOGGER = LogManager.getLogger(GofActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                                CommonAlertTag.WSTG_V42_CONF_04_BACKUP_FILES));
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public AlertThreshold getAlertThreshold() {
        AlertThreshold threshold = super.getAlertThreshold();
        return threshold == AlertThreshold.DEFAULT ? AlertThreshold.OFF : threshold;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(PREFIX + ".soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(PREFIX + ".refs");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 530; // CWE-530: Exposure of Backup File
    }

    @Override
    public int getWascId() {
        return 34; // Predictable Resource Location
    }

    @Override
    public void scan() {
        if (isPage404(getBaseMsg())) {
            return;
        }

        try {
            GofParam config = Model.getSingleton().getOptionsParam().getParamSet(GofParam.class);
            if (config == null) {
                config = new GofParam();
            }
            CandidateGenerator generator = new CandidateGenerator();
            List<FileNameCandidate> candidates =
                    generator.generate(
                            getBaseMsg().getRequestHeader().getURI(), config, getAttackStrength());

            for (FileNameCandidate candidate : candidates) {
                if (isStop()) {
                    return;
                }

                String uriString = candidate.uri().toString();
                if (getKb().get(PREFIX + ".probed." + uriString) != null) {
                    continue;
                }
                getKb().add(PREFIX + ".probed." + uriString, Boolean.TRUE);

                HttpMessage testMsg = getNewMsg();
                testMsg.getRequestHeader().setURI(candidate.uri());

                try {
                    sendAndReceive(testMsg, false);
                } catch (IOException e) {
                    LOGGER.debug("Error probing candidate: {}", uriString, e);
                    continue;
                }

                int statusCode = testMsg.getResponseHeader().getStatusCode();

                if (isPage200(testMsg) && !isPage404(testMsg)) {
                    newAlert()
                            .setRisk(Alert.RISK_MEDIUM)
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setAttack(uriString)
                            .setOtherInfo(
                                    Constant.messages.getString(
                                            PREFIX + ".otherinfo.confirmed",
                                            candidate.kind().getLabel(),
                                            candidate.wordlistEntry()))
                            .setMessage(testMsg)
                            .raise();
                } else if (getAlertThreshold() == AlertThreshold.LOW
                        && (statusCode == HttpStatusCode.UNAUTHORIZED
                                || statusCode == HttpStatusCode.FORBIDDEN)) {
                    newAlert()
                            .setRisk(Alert.RISK_INFO)
                            .setConfidence(Alert.CONFIDENCE_LOW)
                            .setAttack(uriString)
                            .setOtherInfo(
                                    Constant.messages.getString(
                                            PREFIX + ".otherinfo.restricted", statusCode))
                            .setMessage(testMsg)
                            .raise();
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error in GofActiveScanRule scan: {}", e.getMessage(), e);
        }
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                newAlert()
                        .setRisk(Alert.RISK_MEDIUM)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setAttack("https://example.com/index.php.bak")
                        .setOtherInfo(
                                Constant.messages.getString(
                                        PREFIX + ".otherinfo.confirmed",
                                        VariantKind.EXTENSION_APPEND.getLabel(),
                                        "bak"))
                        .build());
    }
}
