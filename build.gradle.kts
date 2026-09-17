import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless") version "6.25.0"
    id("org.zaproxy.common")
}

description = "Good Old Files - organize and reference old files in ZAP"

zapAddOn {
    addOnId.set("gof")
    addOnName.set("Good Old Files")
    zapVersion.set("2.16.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    releaseLink.set("https://github.com/kingthorin/gof/compare/v@PREVIOUS_VERSION@...v@CURRENT_VERSION@")
    unreleasedLink.set("https://github.com/kingthorin/gof/compare/v@CURRENT_VERSION@...HEAD")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/gof/")
        repo.set("https://github.com/kingthorin/gof")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.36.0 & < 2.0.0")
                }
            }
        }
    }
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

spotless {
    kotlinGradle {
        ktlint()
    }
    java {
        // Don't enforce the license, just the format.
        clearSteps()
        googleJavaFormat("1.25.2").aosp()
    }
    format("html", {
        eclipseWtp(EclipseWtpFormatterStep.HTML)
        target(
            fileTree(projectDir) {
                include("src/**/*.html")
            },
        )
    })
}

dependencies {
    compileOnly("org.zaproxy.addon:commonlib:1.36.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.3")
    testImplementation("org.assertj:assertj-core:3.24.1")
}

tasks.test {
    useJUnitPlatform()
}
