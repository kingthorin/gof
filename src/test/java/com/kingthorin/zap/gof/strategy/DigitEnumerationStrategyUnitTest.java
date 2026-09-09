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
class DigitEnumerationStrategyUnitTest {

    @Test
    void testDigitEnumerationLastDigit() throws Exception {
        DigitEnumerationStrategy strategy = new DigitEnumerationStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/file1.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).hasSize(9);
        assertThat(candidates).anyMatch(c -> c.uri().toString().contains("file0.php"));
        assertThat(candidates).anyMatch(c -> c.uri().toString().contains("file2.php"));
    }

    @Test
    void testDigitEnumerationMiddleDigit() throws Exception {
        DigitEnumerationStrategy strategy = new DigitEnumerationStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/file1name.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates)
                .hasSize(9)
                .filteredOn(c -> c.uri().toString().contains("file0name.php"))
                .hasSize(1);
    }

    @Test
    void testDigitEnumerationNoOp() throws Exception {
        DigitEnumerationStrategy strategy = new DigitEnumerationStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/nodigits.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).isEmpty();
    }

    @Test
    void testEmptyFilenameNoOp() throws Exception {
        DigitEnumerationStrategy strategy = new DigitEnumerationStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/admin/"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).isEmpty();
    }

    @Test
    void testDigitEnumerationPreservesOriginal() throws Exception {
        DigitEnumerationStrategy strategy = new DigitEnumerationStrategy();
        PathParts parts = PathParts.from(new URI("https://example.com/file1.php"));
        GofParam config = new GofParam();

        List<FileNameCandidate> candidates = strategy.generate(parts, config);

        assertThat(candidates).noneMatch(c -> c.uri().toString().contains("file1.php"));
    }

    @Test
    void testStrategyKind() {
        DigitEnumerationStrategy strategy = new DigitEnumerationStrategy();

        assertThat(strategy.kind()).isEqualTo(VariantKind.DIGIT_ENUMERATION);
    }
}
