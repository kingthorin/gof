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
package com.kingthorin.zap.gof.model;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

public record PathParts(
        String scheme,
        String host,
        int port,
        String directoryPath,
        String parentDirName,
        String filename,
        String baseName,
        String extension) {

    public static PathParts from(URI uri) throws URIException {
        String scheme = uri.getScheme();
        String host = uri.getHost();
        int port = uri.getPort();

        String path = uri.getPath();
        if (path == null) {
            path = "";
        }

        String directoryPath = path;
        String parentDirName = "";
        String filename = "";
        String baseName = "";
        String fileExtension = "";

        if (!path.isEmpty() && !path.equals("/")) {
            int lastSlashIndex = path.lastIndexOf('/');
            if (lastSlashIndex >= 0) {
                if (lastSlashIndex == path.length() - 1) {
                    directoryPath = path;
                    parentDirName = extractParentDirName(path);
                } else {
                    directoryPath = path.substring(0, lastSlashIndex + 1);
                    filename = path.substring(lastSlashIndex + 1);
                    parentDirName = extractParentDirName(path.substring(0, lastSlashIndex));

                    int dotIndex = filename.lastIndexOf('.');
                    if (dotIndex > 0) {
                        baseName = filename.substring(0, dotIndex);
                        fileExtension = filename.substring(dotIndex);
                    } else {
                        baseName = filename;
                    }
                }
            }
        }

        return new PathParts(
                scheme,
                host,
                port,
                directoryPath,
                parentDirName,
                filename,
                baseName,
                fileExtension);
    }

    private static String extractParentDirName(String path) {
        if (path == null || path.isEmpty() || path.equals("/")) {
            return "";
        }
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == path.length() - 1) {
            return "";
        }
        return path.substring(lastSlash + 1);
    }
}
