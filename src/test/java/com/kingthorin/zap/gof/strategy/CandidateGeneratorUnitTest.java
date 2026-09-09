/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import static org.assertj.core.api.Assertions.assertThat;

import com.kingthorin.zap.gof.config.GofParam;
import com.kingthorin.zap.gof.model.FileNameCandidate;
import com.kingthorin.zap.gof.model.VariantKind;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin;

@SuppressWarnings("deprecation")
class CandidateGeneratorUnitTest {

    @Test
    void testCappingLowAttackStrength() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        URI uri = new URI("https://example.com/login.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.LOW);

        assertThat(candidates.size()).isLessThanOrEqualTo(6);
    }

    @Test
    void testCappingMediumAttackStrength() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        URI uri = new URI("https://example.com/login.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.MEDIUM);

        assertThat(candidates.size()).isLessThanOrEqualTo(12);
    }

    @Test
    void testCappingHighAttackStrength() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        URI uri = new URI("https://example.com/login.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.HIGH);

        assertThat(candidates.size()).isLessThanOrEqualTo(20);
    }

    @Test
    void testNoDuplicateUris() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        URI uri = new URI("https://example.com/login.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.HIGH);

        Set<String> uris = new HashSet<>();
        for (FileNameCandidate candidate : candidates) {
            uris.add(candidate.uri().toString());
        }

        assertThat(uris).hasSameSizeAs(candidates);
    }

    @Test
    void testGeneratesAtLeastSomeCandidates() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        URI uri = new URI("https://example.com/app.jar");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.MEDIUM);

        assertThat(candidates).hasSize(6);
    }

    @Test
    void testExtensionCombinationStrategyIncluded() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        config.setExtensionCombinationEnabled(true);
        URI uri = new URI("https://example.com/login.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.HIGH);

        assertThat(candidates)
                .anyMatch(
                        c ->
                                c.uri().toString().contains("login_old.php")
                                        || c.uri().toString().contains("login.old.php"));
    }

    @Test
    void testDigitEnumerationStrategyIncluded() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        config.setDigitEnumerationEnabled(true);
        URI uri = new URI("https://example.com/file1.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.HIGH);

        assertThat(candidates)
                .anySatisfy(c -> assertThat(c.uri().toString()).contains("file0.php"));
    }

    @Test
    void testExtensionCombinationDisabled() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        config.setExtensionCombinationEnabled(false);
        URI uri = new URI("https://example.com/login.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.HIGH);

        assertThat(candidates)
                .noneMatch(
                        c ->
                                c.uri().toString().contains("login_old.php")
                                        && c.kind().equals(VariantKind.EXTENSION_COMBINATION));
    }

    @Test
    void testDigitEnumerationDisabled() throws Exception {
        CandidateGenerator generator = new CandidateGenerator();
        GofParam config = new GofParam();
        config.setDigitEnumerationEnabled(false);
        URI uri = new URI("https://example.com/file1.php");

        List<FileNameCandidate> candidates =
                generator.generate(uri, config, Plugin.AttackStrength.HIGH);

        assertThat(candidates)
                .noneSatisfy(c -> assertThat(c.uri().toString()).contains("file0.php"));
    }
}
