plugins {
    java
    id("com.gradleup.shadow") version "9.1.0"
}

group = "com.comint"
version = "1.0.0"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

dependencies {
    // Burp API — provided by Burp at runtime, must NOT be bundled
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // Protocol codec libraries (bundled into fat JAR, relocated below)
    implementation("com.google.protobuf:protobuf-java:4.29.3")
    implementation("com.google.protobuf:protobuf-java-util:4.29.3")
    implementation("org.msgpack:msgpack-core:0.9.8")
    implementation("org.msgpack:jackson-dataformat-msgpack:0.9.8")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("com.graphql-java:graphql-java:22.3")

    // Tests
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-core:5.14.0")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.2")
}

tasks.shadowJar {
    mergeServiceFiles()
    // Burp provides Montoya at runtime — never bundle it
    dependencies {
        exclude(dependency("net.portswigger.burp.extensions:montoya-api"))
    }
    // Relocate to avoid clashing with classes Burp loads internally
    relocate("com.google.protobuf", "com.comint.shaded.protobuf")
    relocate("com.fasterxml.jackson", "com.comint.shaded.jackson")
    relocate("org.msgpack", "com.comint.shaded.msgpack")
    relocate("graphql", "com.comint.shaded.graphql")
    relocate("org.antlr", "com.comint.shaded.antlr")
    relocate("org.reactivestreams", "com.comint.shaded.reactivestreams")
    relocate("org.dataloader", "com.comint.shaded.dataloader")
    relocate("com.github.benmanes.caffeine", "com.comint.shaded.caffeine")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

tasks.test {
    useJUnitPlatform()
}
