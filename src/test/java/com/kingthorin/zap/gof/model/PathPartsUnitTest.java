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
package com.kingthorin.zap.gof.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
class PathPartsUnitTest {

    @Test
    void testFileWithExtension() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com/admin/login.php"));

        assertThat(parts.scheme()).isEqualTo("https");
        assertThat(parts.host()).isEqualTo("example.com");
        assertThat(parts.directoryPath()).isEqualTo("/admin/");
        assertThat(parts.parentDirName()).isEqualTo("admin");
        assertThat(parts.filename()).isEqualTo("login.php");
        assertThat(parts.baseName()).isEqualTo("login");
        assertThat(parts.extension()).isEqualTo("php");
    }

    @Test
    void testFileWithoutExtension() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com/admin/README"));

        assertThat(parts.filename()).isEqualTo("README");
        assertThat(parts.baseName()).isEqualTo("README");
        assertThat(parts.extension()).isEmpty();
    }

    @Test
    void testDirectoryOnly() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com/admin/"));

        assertThat(parts.directoryPath()).isEqualTo("/admin/");
        assertThat(parts.parentDirName()).isEqualTo("admin");
        assertThat(parts.filename()).isEmpty();
        assertThat(parts.baseName()).isEmpty();
        assertThat(parts.extension()).isEmpty();
    }

    @Test
    void testRootPath() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com/"));

        assertThat(parts.directoryPath()).isEqualTo("/");
        assertThat(parts.parentDirName()).isEmpty();
        assertThat(parts.filename()).isEmpty();
    }

    @Test
    void testFileWithMultipleDots() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com/app/config.prod.yaml"));

        assertThat(parts.filename()).isEqualTo("config.prod.yaml");
        assertThat(parts.baseName()).isEqualTo("config.prod");
        assertThat(parts.extension()).isEqualTo("yaml");
    }

    @Test
    void testDefaultPortHttp() throws Exception {
        PathParts parts = PathParts.from(new URI("http://example.com/index.html"));

        assertThat(parts.port()).isEqualTo(-1);
    }

    @Test
    void testExplicitPort() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com:8443/page.html"));

        assertThat(parts.port()).isEqualTo(8443);
    }

    @Test
    void testNestedDirectories() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com/a/b/c/file.txt"));

        assertThat(parts.directoryPath()).isEqualTo("/a/b/c/");
        assertThat(parts.parentDirName()).isEqualTo("c");
        assertThat(parts.filename()).isEqualTo("file.txt");
    }

    @Test
    void testHiddenFile() throws Exception {
        PathParts parts = PathParts.from(new URI("https://example.com/.htaccess"));

        assertThat(parts.filename()).isEqualTo(".htaccess");
        assertThat(parts.baseName()).isEqualTo(".htaccess");
        assertThat(parts.extension()).isEmpty();
    }
}
