def getMessage(String status) {
  switch (status) {
  case 'SUCCESS':
    return 'Success.'
    break
  case 'FAILURE':
    return 'Build failed.'
    break
  case 'PENDING':
    return 'Build is pending.'
    break
  default:
    return state
    break
  }
}

def notify(String context, String status) {
  step([
    $class: "GitHubCommitStatusSetter",
    contextSource: [
      $class: "ManuallyEnteredCommitContextSource", context: "ci/" + context
    ],
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
        [$class: "AnyBuildResult", message: getMessage(message), state: state]
      ]
    ]
  ]);
}
