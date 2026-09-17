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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;

@SuppressWarnings("deprecation")
class GofActiveScanRuleUnitTest {

    @Test
    void testKnownNodeIsRecognised() throws Exception {
        // A candidate that was already spidered/proxied before the scan ran (e.g. home2.jpg
        // legitimately existing alongside home1.jpg/home3.jpg) must not be treated as a
        // discovered backup file.
        SiteMap siteTree = mock(SiteMap.class);
        URI uri = new URI("https://example.com/home2.jpg", false);
        when(siteTree.findNode(uri)).thenReturn(mock(SiteNode.class));

        assertThat(GofActiveScanRule.isKnownNode(siteTree, uri)).isTrue();
    }

    @Test
    void testUnknownNodeIsNotRecognised() throws Exception {
        SiteMap siteTree = mock(SiteMap.class);
        URI uri = new URI("https://example.com/home1.jpg.bak", false);
        when(siteTree.findNode(uri)).thenReturn(null);

        assertThat(GofActiveScanRule.isKnownNode(siteTree, uri)).isFalse();
    }
}
