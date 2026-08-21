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
package com.github.kingthorin.zap.gof.strategy;

import com.github.kingthorin.zap.gof.config.GofParam;
import com.github.kingthorin.zap.gof.model.FileNameCandidate;
import com.github.kingthorin.zap.gof.model.PathParts;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;

public class CandidateGenerator {

    private static final int[] STRENGTH_LIMITS = {6, 12, 20, Integer.MAX_VALUE};

    public List<FileNameCandidate> generate(URI baseUri, GofParam config, AttackStrength strength)
            throws URIException {
        PathParts parts = PathParts.from(baseUri);

        List<VariantStrategy> strategies = new ArrayList<>();
        if (config.isExtensionAppendEnabled()) {
            strategies.add(new ExtensionAppendStrategy());
        }
        if (config.isExtensionReplaceEnabled()) {
            strategies.add(new ExtensionReplaceStrategy());
        }
        if (config.isExtensionSwitchEnabled()) {
            strategies.add(new ExtensionSwitchStrategy());
        }
        if (config.isFilenameSuffixEnabled()) {
            strategies.add(new FilenameSuffixStrategy());
        }
        if (config.isFilenamePrefixEnabled()) {
            strategies.add(new FilenamePrefixStrategy());
        }
        if (config.isDirectorySuffixEnabled()) {
            strategies.add(new DirectorySuffixStrategy());
        }
        if (config.isDirectoryPrefixEnabled()) {
            strategies.add(new DirectoryPrefixStrategy());
        }

        Set<String> deduped = new LinkedHashSet<>();
        List<FileNameCandidate> result = new ArrayList<>();
        int limit = STRENGTH_LIMITS[strength.ordinal()];

        for (VariantStrategy strategy : strategies) {
            for (FileNameCandidate candidate : strategy.generate(parts, config)) {
                String key = candidate.uri().toString();
                if (!deduped.contains(key)) {
                    deduped.add(key);
                    result.add(candidate);
                    if (result.size() >= limit) {
                        return result;
                    }
                }
            }
        }

        return result;
    }
}
