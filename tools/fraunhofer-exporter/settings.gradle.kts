pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        ivy {
            setUrl("https://download.eclipse.org/tools/cdt/releases/")
            metadataSources {
                artifact()
            }
            patternLayout {
                artifact("[organisation].[module]_[revision].[ext]")
            }
        }
    }
}

rootProject.name = "fraunhofer-exporter"
