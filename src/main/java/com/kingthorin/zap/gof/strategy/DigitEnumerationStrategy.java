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
package com.kingthorin.zap.gof.strategy;

import com.kingthorin.zap.gof.config.GofParam;
import com.kingthorin.zap.gof.model.FileNameCandidate;
import com.kingthorin.zap.gof.model.PathParts;
import com.kingthorin.zap.gof.model.VariantKind;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

public class DigitEnumerationStrategy implements VariantStrategy {

    @Override
    public VariantKind kind() {
        return VariantKind.DIGIT_ENUMERATION;
    }

    @Override
    public List<FileNameCandidate> generate(PathParts parts, GofParam config) {
        List<FileNameCandidate> candidates = new ArrayList<>();

        if (parts.filename().isEmpty()) {
            return candidates;
        }

        String baseName = parts.baseName();
        String ext = parts.extension();

        char[] baseNameArray = baseName.toCharArray();
        for (int i = 0; i < baseName.length(); i++) {
            if (Character.isDigit(baseNameArray[i])) {
                if (i == (baseName.length() - 1) || !Character.isDigit(baseNameArray[i + 1])) {
                    char original = baseNameArray[i];

                    for (int charCode = (int) '0'; charCode <= (int) '9'; charCode++) {
                        if (charCode == (int) original) {
                            continue;
                        }

                        baseNameArray[i] = (char) charCode;
                        String candidateFilename =
                                new String(baseNameArray) + (ext.isEmpty() ? "" : "." + ext);

                        try {
                            URI candidateUri =
                                    new URI(
                                            parts.scheme(),
                                            null,
                                            parts.host(),
                                            parts.port(),
                                            parts.directoryPath() + candidateFilename,
                                            null,
                                            null);
                            candidates.add(
                                    new FileNameCandidate(candidateUri, kind(), candidateFilename));
                        } catch (URIException e) {
                            // Skip malformed URIs
                        }
                    }

                    baseNameArray[i] = original;
                }
            }
        }

        return candidates;
    }
}
