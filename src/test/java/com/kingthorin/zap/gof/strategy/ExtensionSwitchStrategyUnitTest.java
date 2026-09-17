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

import static org.assertj.core.api.Assertions.assertThat;

import com.kingthorin.zap.gof.config.GofParam;
import com.kingthorin.zap.gof.model.FileNameCandidate;
import com.kingthorin.zap.gof.model.PathParts;
import com.kingthorin.zap.gof.model.VariantKind;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
class ExtensionSwitchStrategyUnitTest {

    @Test
    void testSwitchesToOtherExtensions() throws Exception {
        ExtensionSwitchStrategy strategy = new ExtensionSwitchStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/login.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates)
                .anyMatch(c -> c.uri().toString().equals("https://example.com/login.asp"));
        assertThat(candidates).allMatch(c -> c.kind() == VariantKind.EXTENSION_SWITCH);
    }

    @Test
    void testDoesNotSwitchToSameExtension() throws Exception {
        ExtensionSwitchStrategy strategy = new ExtensionSwitchStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/login.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates)
                .noneMatch(c -> c.uri().toString().equals("https://example.com/login.php"));
        assertThat(candidates).hasSize(config.getEffectiveSwitchExtensions().size() - 1);
    }

    @Test
    void testEmptyFilenameNoOp() throws Exception {
        ExtensionSwitchStrategy strategy = new ExtensionSwitchStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/admin/"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).isEmpty();
    }

    @Test
    void testFileWithoutExtensionNoOp() throws Exception {
        ExtensionSwitchStrategy strategy = new ExtensionSwitchStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/README"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).isEmpty();
    }

    @Test
    void testStrategyKind() {
        ExtensionSwitchStrategy strategy = new ExtensionSwitchStrategy();

        assertThat(strategy.kind()).isEqualTo(VariantKind.EXTENSION_SWITCH);
    }
}
