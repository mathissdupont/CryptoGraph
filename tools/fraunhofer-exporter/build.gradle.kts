plugins {
    kotlin("jvm") version "2.0.21"
    application
    id("com.gradleup.shadow") version "8.3.5"
}

group = "io.cryptograph"
version = "0.1.0"

dependencies {
    implementation("de.fraunhofer.aisec:cpg-core:9.0.2")
    implementation("de.fraunhofer.aisec:cpg-language-python:9.0.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.2")
}

application {
    mainClass.set("io.cryptograph.exporter.MainKt")
}

tasks.shadowJar {
    archiveFileName.set("fraunhofer-exporter.jar")
    archiveClassifier.set("all")
    mergeServiceFiles()
    manifest {
        attributes["Main-Class"] = "io.cryptograph.exporter.MainKt"
    }
}

kotlin {
    jvmToolchain(17)
}
