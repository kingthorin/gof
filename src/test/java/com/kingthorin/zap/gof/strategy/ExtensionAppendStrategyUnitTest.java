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
import com.kingthorin.zap.gof.model.PathParts;
import com.kingthorin.zap.gof.model.VariantKind;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
class ExtensionAppendStrategyUnitTest {

    @Test
    void testExtensionAppendWithDotPrefix() throws Exception {
        ExtensionAppendStrategy strategy = new ExtensionAppendStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/login.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).hasSize(config.getEffectiveBackupExtensions().size());
        assertThat(candidates)
                .anyMatch(c -> c.uri().toString().equals("https://example.com/login.php.bak"));
        assertThat(candidates.get(0).kind()).isEqualTo(VariantKind.EXTENSION_APPEND);
    }

    @Test
    void testExtensionAppendWithoutDotPrefix() throws Exception {
        ExtensionAppendStrategy strategy = new ExtensionAppendStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/login.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates)
                .anyMatch(c -> c.uri().toString().contains("login.php.bak"))
                .anyMatch(c -> c.uri().toString().contains("login.php.backup"));
    }

    @Test
    void testEmptyFilenameNoOp() throws Exception {
        ExtensionAppendStrategy strategy = new ExtensionAppendStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/admin/"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).isEmpty();
    }

    @Test
    void testFileWithoutExtension() throws Exception {
        ExtensionAppendStrategy strategy = new ExtensionAppendStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/README"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).hasSize(config.getEffectiveBackupExtensions().size());
        assertThat(candidates)
                .anyMatch(c -> c.uri().toString().equals("https://example.com/README.bak"));
    }

    @Test
    void testStrategyKind() {
        ExtensionAppendStrategy strategy = new ExtensionAppendStrategy();

        assertThat(strategy.kind()).isEqualTo(VariantKind.EXTENSION_APPEND);
    }
}
