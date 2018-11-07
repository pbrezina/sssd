void notifyGithub(String os, String state)
{
  def message
  switch (state) {
  case 'SUCCESS':
    message = 'Success.'
    break
  case 'FAILURE':
    message = 'Build failed.'
    break
  case 'PENDING':
    message = 'Build is pending.'
    break
  default:
    message = state
    break
  }    

  step([
      $class: "GitHubCommitStatusSetter",
      contextSource: [$class: "ManuallyEnteredCommitContextSource", context: "ci/" + os],
      errorHandlers: [
        [$class: "ChangingBuildStatusErrorHandler", result: "UNSTABLE"]
      ],
      statusBackrefSource: [
        $class: "ManuallyEnteredBackrefSource",
        backref: "${env.RUN_DISPLAY_URL}"
      ],
      statusResultSource: [
        $class: "ConditionalStatusResultSource",
        results: [
          [$class: "AnyBuildResult", message: message, state: state]
        ]
      ]
  ]);
}



pipeline {
  agent none
  options {
    timeout(time: 10, unit: 'HOURS')
    checkoutToSubdirectory('sssd')
    skipDefaultCheckout()
  }
  environment {
    SUITE_DIR     = "/jenkins/sssd-test-suite"
    RUN           = "./contrib/test-suite/run.sh"
  }
  stages {
    stage('Run Tests') {
      parallel {
        stage('Test on Fedora 28') {
          agent {label "sssd-ci"}
          environment {
            TEST_SYSTEM = 'fedora28'
            CONFIG      = '/jenkins/configs/config-f28.json'
          }
          steps {
            notifyGithub("${env.TEST_SYSTEM}", 'PENDING')
            checkout scm
            sh '$RUN "$WORKSPACE/sssd" "$SUITE_DIR" "$WORKSPACE/artifacts" "$CONFIG"'
          }
          post {
            failure {
              archiveArtifacts artifacts: "artifacts/**", allowEmptyArchive: true
              notifyGithub("${env.TEST_SYSTEM}", 'FAILURE')
            }
            success {
              notifyGithub("${env.TEST_SYSTEM}", 'SUCCESS')
            }
          }
        }
      }
    }
  }
}
