/**
 * Workaround for https://issues.jenkins-ci.org/browse/JENKINS-39203
 *
 * At this moment if one stage in parallel block fails, failure branch in
 * post block is run in all stages even though they might have been successful.
 *
 * We remember result of test stages in this variable so we can correctly
 * report a success or error even if one of the stages that are run in
 * parallel failed.
 */
def ci_result = [:]

/**
 * Remember that the build failed because one of the untrusted files were 
 * modified.
 */
def untrusted = false

pipeline {
  agent none
  options {
    timeout(time: 10, unit: 'HOURS')
    checkoutToSubdirectory('sssd')
  }
  environment {
    NAME       = "$BRANCH_NAME/$BUILD_ID"
    BASE_DIR   = "/home/fedora"
    GH_CONTEXT = "sssd-ci"
    GH_SUCCESS = "Success."
    GH_PENDING = "Build is pending."
    GH_FAILURE = "Build failed."
    GH_ABORTED = "Aborted."
    GH_URL     = "https://pagure.io/SSSD/sssd"
    AWS_BASE   = "https://s3.eu-central-1.amazonaws.com/sssd-ci"
    SUITE_DIR  = "$BASE_DIR/sssd-test-suite"
    ARCHIVE    = "$BASE_DIR/scripts/archive.sh"
    RUN        = "./sssd/contrib/test-suite/run.sh"
  }
  stages {
    stage('Prepare') {
      steps {
        githubNotify status: 'PENDING', context: "$GH_CONTEXT", description: 'Running tests.', targetUrl: "$GH_URL"
      }
    }
    stage('Read trusted files') {
      steps {
        readTrusted './contrib/test-suite/run.sh'
        readTrusted './contrib/test-suite/run-client.sh'
      }
      post {
        failure {
          script {
            untrusted = true
          }
        }
      }
    }
    stage('Run Tests') {
      parallel {
        stage('Test on Fedora 28') {
          agent {label "sssd-ci"}
          environment {
            TEST_SYSTEM = "fedora28"
            GH_CONTEXT  = "$GH_CONTEXT/fedora28"
            GH_URL      = "$AWS_BASE/$BRANCH_NAME/$BUILD_ID/$TEST_SYSTEM/index.html"
            CONFIG      = "$BASE_DIR/configs/${TEST_SYSTEM}.json"
          }
          steps {
            githubNotify status: 'PENDING', context: "$GH_CONTEXT", description: "$GH_PENDING", targetUrl: "$GH_URL"
            sh '$RUN "$WORKSPACE/sssd" "$SUITE_DIR" "$WORKSPACE/artifacts/$TEST_SYSTEM" "$CONFIG"'
            script {
              ci_result[env.TEST_SYSTEM] = "success"
            }
          }
          post {
            always {
              archiveArtifacts artifacts: "artifacts/**", allowEmptyArchive: true
              sh '$ARCHIVE $TEST_SYSTEM $WORKSPACE/artifacts/$TEST_SYSTEM $NAME'
              sh 'rm -fr "$WORKSPACE/artifacts/$TEST_SYSTEM"'

              script {
                if (ci_result[env.TEST_SYSTEM] == "success") {
                  githubNotify status: 'SUCCESS', context: "$GH_CONTEXT", description: "$GH_SUCCESS", targetUrl: "$GH_URL"
                } else {
                  githubNotify status: 'FAILURE', context: "$GH_CONTEXT", description: "$GH_FAILURE", targetUrl: "$GH_URL"
                }
              }
            }
            aborted {
              githubNotify status: 'ERROR', context: "$GH_CONTEXT", description: "$GH_ABORTED", targetUrl: "$GH_URL"
            }
          }
        }
        stage('Test on Fedora 29') {
          agent {label "sssd-ci"}
          environment {
            TEST_SYSTEM = "fedora29"
            GH_CONTEXT  = "$GH_CONTEXT/fedora29"
            GH_URL      = "$AWS_BASE/$BRANCH_NAME/$BUILD_ID/$TEST_SYSTEM/index.html"
            CONFIG      = "$BASE_DIR/configs/${TEST_SYSTEM}.json"
          }
          steps {
            githubNotify status: 'PENDING', context: "$GH_CONTEXT", description: "$GH_PENDING", targetUrl: "$GH_URL"
            sh '$RUN "$WORKSPACE/sssd" "$SUITE_DIR" "$WORKSPACE/artifacts/$TEST_SYSTEM" "$CONFIG"'
            script {
              ci_result[env.TEST_SYSTEM] = "success"
            }
          }
          post {
            always {
              archiveArtifacts artifacts: "artifacts/**", allowEmptyArchive: true
              sh '$ARCHIVE $TEST_SYSTEM $WORKSPACE/artifacts/$TEST_SYSTEM $NAME'
              sh 'rm -fr "$WORKSPACE/artifacts/$TEST_SYSTEM"'

              script {
                if (ci_result[env.TEST_SYSTEM] == "success") {
                  githubNotify status: 'SUCCESS', context: "$GH_CONTEXT", description: "$GH_SUCCESS", targetUrl: "$GH_URL"
                } else {
                  githubNotify status: 'FAILURE', context: "$GH_CONTEXT", description: "$GH_FAILURE", targetUrl: "$GH_URL"
                }
              }
            }
            aborted {
              githubNotify status: 'ERROR', context: "$GH_CONTEXT", description: "$GH_ABORTED", targetUrl: "$GH_URL"
            }
          }
        }
        stage('Test on Fedora 30') {
          agent {label "sssd-ci"}
          environment {
            TEST_SYSTEM = "fedora30"
            GH_CONTEXT  = "$GH_CONTEXT/fedora30"
            GH_URL      = "$AWS_BASE/$BRANCH_NAME/$BUILD_ID/$TEST_SYSTEM/index.html"
            CONFIG      = "$BASE_DIR/configs/${TEST_SYSTEM}.json"
          }
          steps {
            githubNotify status: 'PENDING', context: "$GH_CONTEXT", description: "$GH_PENDING", targetUrl: "$GH_URL"
            sh '$RUN "$WORKSPACE/sssd" "$SUITE_DIR" "$WORKSPACE/artifacts/$TEST_SYSTEM" "$CONFIG"'
            script {
              ci_result[env.TEST_SYSTEM] = "success"
            }
          }
          post {
            always {
              archiveArtifacts artifacts: "artifacts/**", allowEmptyArchive: true
              sh '$ARCHIVE $TEST_SYSTEM $WORKSPACE/artifacts/$TEST_SYSTEM $NAME'
              sh 'rm -fr "$WORKSPACE/artifacts/$TEST_SYSTEM"'

              script {
                if (ci_result[env.TEST_SYSTEM] == "success") {
                  githubNotify status: 'SUCCESS', context: "$GH_CONTEXT", description: "$GH_SUCCESS", targetUrl: "$GH_URL"
                } else {
                  githubNotify status: 'FAILURE', context: "$GH_CONTEXT", description: "$GH_FAILURE", targetUrl: "$GH_URL"
                }
              }
            }
            aborted {
              githubNotify status: 'ERROR', context: "$GH_CONTEXT", description: "$GH_ABORTED", targetUrl: "$GH_URL"
            }
          }
        }
        stage('Test on Fedora Rawhide') {
          agent {label "sssd-ci"}
          environment {
            TEST_SYSTEM = "fedora-rawhide"
            GH_CONTEXT  = "$GH_CONTEXT/fedora-rawhide"
            GH_URL      = "$AWS_BASE/$BRANCH_NAME/$BUILD_ID/$TEST_SYSTEM/index.html"
            CONFIG      = "$BASE_DIR/configs/${TEST_SYSTEM}.json"
          }
          steps {
            githubNotify status: 'PENDING', context: "$GH_CONTEXT", description: "$GH_PENDING", targetUrl: "$GH_URL"
            sh '$RUN "$WORKSPACE/sssd" "$SUITE_DIR" "$WORKSPACE/artifacts/$TEST_SYSTEM" "$CONFIG"'
            script {
              ci_result[env.TEST_SYSTEM] = "success"
            }
          }
          post {
            always {
              archiveArtifacts artifacts: "artifacts/**", allowEmptyArchive: true
              sh '$ARCHIVE $TEST_SYSTEM $WORKSPACE/artifacts/$TEST_SYSTEM $NAME'
              sh 'rm -fr "$WORKSPACE/artifacts/$TEST_SYSTEM"'

              script {
                if (ci_result[env.TEST_SYSTEM] == "success") {
                  githubNotify status: 'SUCCESS', context: "$GH_CONTEXT", description: "$GH_SUCCESS", targetUrl: "$GH_URL"
                } else {
                  githubNotify status: 'FAILURE', context: "$GH_CONTEXT", description: "$GH_FAILURE", targetUrl: "$GH_URL"
                }
              }
            }
            aborted {
              githubNotify status: 'ERROR', context: "$GH_CONTEXT", description: "$GH_ABORTED", targetUrl: "$GH_URL"
            }
          }
        }
      }
    }
  }
  post {
    failure {
      script {
        if (untrusted) {
          githubNotify status: 'ERROR', context: "$GH_CONTEXT", description: 'Untrusted files were modified.', targetUrl: "$GH_URL"
        } else {
          githubNotify status: 'FAILURE', context: "$GH_CONTEXT", description: 'Some tests failed.', targetUrl: "$GH_URL"
        }
      }
    }
    aborted {
      githubNotify status: 'ERROR', context: "$GH_CONTEXT", description: 'Builds were aborted.', targetUrl: "$GH_URL"
    }
    success {
      githubNotify status: 'SUCCESS', context: "$GH_CONTEXT", description: 'All tests succeeded.', targetUrl: "$GH_URL"
    }
  }
}
