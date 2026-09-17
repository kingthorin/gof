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
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;

public class CandidateGenerator {

    private static int limitFor(AttackStrength strength) {
        return switch (strength) {
            case LOW -> 15;
            case MEDIUM, DEFAULT -> 35;
            case HIGH -> 75;
            case INSANE -> Integer.MAX_VALUE;
        };
    }

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
        if (config.isExtensionCombinationEnabled()) {
            strategies.add(new ExtensionCombinationStrategy());
        }
        if (config.isFilenameSuffixEnabled()) {
            strategies.add(new FilenameSuffixStrategy());
        }
        if (config.isFilenamePrefixEnabled()) {
            strategies.add(new FilenamePrefixStrategy());
        }
        if (config.isDigitEnumerationEnabled()) {
            strategies.add(new DigitEnumerationStrategy());
        }
        if (config.isDirectorySuffixEnabled()) {
            strategies.add(new DirectorySuffixStrategy());
        }
        if (config.isDirectoryPrefixEnabled()) {
            strategies.add(new DirectoryPrefixStrategy());
        }

        List<List<FileNameCandidate>> perStrategy = new ArrayList<>(strategies.size());
        for (VariantStrategy strategy : strategies) {
            perStrategy.add(strategy.generate(parts, config));
        }

        Set<String> deduped = new LinkedHashSet<>();
        List<FileNameCandidate> result = new ArrayList<>();
        int limit = limitFor(strength);
        int[] indices = new int[perStrategy.size()];

        // Round-robin across strategies so the limit doesn't let early strategies (e.g.
        // extension-based, which can produce dozens of candidates) starve out later ones
        // (e.g. filename/directory prefixes) before they get a chance to contribute.
        boolean progress = true;
        while (progress && result.size() < limit) {
            progress = false;
            for (int i = 0; i < perStrategy.size() && result.size() < limit; i++) {
                List<FileNameCandidate> candidates = perStrategy.get(i);
                if (indices[i] < candidates.size()) {
                    FileNameCandidate candidate = candidates.get(indices[i]++);
                    progress = true;
                    if (deduped.add(candidate.uri().toString())) {
                        result.add(candidate);
                    }
                }
            }
        }

        return result;
    }
}
