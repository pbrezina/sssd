pipeline {
  agent none
  options {
    timeout(time: 10, unit: 'HOURS')
    checkoutToSubdirectory('sssd')
  }
  environment {
    GH_CONTEXT = "sssd-ci"
    GH_SUCCESS = "Success."
    GH_PENDING = "Build is pending."
    GH_FAILURE = "Build failed."
    SUITE_DIR  = "/jenkins/sssd-test-suite"
    RUN        = "./sssd/contrib/test-suite/run.sh"
  }
  stages {
    stage('Prepare') {
      steps {
        githubNotify status: 'PENDING', context: 'sssd-ci', description: 'Running tests.'
        readTrusted './contrib/test-suite/run.sh'
        readTrusted './contrib/test-suite/run-client.sh'
        readTrusted './a.sh'
      }
    }
    stage('Run Tests') {
      parallel {
        stage('Test on Fedora 28') {
          agent {label "sssd-ci"}
          environment {
            GH_CONTEXT  = "${env.GH_CONTEXT}/fedora28"
            CONFIG      = '/jenkins/configs/config-f28.json'
          }
          steps {
            githubNotify status: 'PENDING', context: "${env.GH_CONTEXT}", description: "${env.GH_PENDING}"
            sh './sssd/a.sh'
            sh '$RUN "$WORKSPACE/sssd" "$SUITE_DIR" "$WORKSPACE/artifacts/$TEST_SYSTEM" "$CONFIG"'
          }
          post {
            aborted {
              githubNotify status: 'ERROR', context: "${env.GH_CONTEXT}", description: 'Aborted.'
            }
            failure {
              archiveArtifacts artifacts: "artifacts/**", allowEmptyArchive: true
              githubNotify status: 'FAILURE', context: "${env.GH_CONTEXT}", description: "${env.GH_FAILURE}"
            }
            success {
              githubNotify status: 'SUCCESS', context: "${env.GH_CONTEXT}", description: "${env.GH_SUCCESS}"
            }
          }
        }
      }
    }
  }
  post {
    aborted {
      githubNotify status: 'ERROR', context: "${env.GH_CONTEXT}", description: 'Aborted.'
    }
    failure {
      githubNotify status: 'FAILURE', context: "${env.GH_CONTEXT}", description: 'Some tests failed.'
    }
    success {
      githubNotify status: 'SUCCESS', context: "${env.GH_CONTEXT}", description: 'All tests succeeded'
    }
  }
}
