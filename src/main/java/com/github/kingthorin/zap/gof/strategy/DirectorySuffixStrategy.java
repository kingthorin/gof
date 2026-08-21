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
package com.github.kingthorin.zap.gof.strategy;

import com.github.kingthorin.zap.gof.config.GofParam;
import com.github.kingthorin.zap.gof.model.FileNameCandidate;
import com.github.kingthorin.zap.gof.model.PathParts;
import com.github.kingthorin.zap.gof.model.VariantKind;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;

public class DirectorySuffixStrategy implements VariantStrategy {

    @Override
    public VariantKind kind() {
        return VariantKind.DIRECTORY_SUFFIX;
    }

    @Override
    public List<FileNameCandidate> generate(PathParts parts, GofParam config) {
        List<FileNameCandidate> candidates = new ArrayList<>();

        if (parts.parentDirName().isEmpty()) {
            return candidates;
        }

        for (String suffix : config.getEffectiveDirectorySuffixes()) {
            String parentPath = parts.directoryPath();
            if (parentPath.endsWith("/")) {
                parentPath = parentPath.substring(0, parentPath.length() - 1);
            }
            String newPath = parentPath + suffix + "/";
            try {
                URI candidateUri =
                        new URI(
                                parts.scheme(),
                                null,
                                parts.host(),
                                parts.port(),
                                newPath,
                                null,
                                null);
                candidates.add(new FileNameCandidate(candidateUri, kind(), suffix));
            } catch (Exception e) {
                // Skip malformed URIs
            }
        }

        return candidates;
    }
}
