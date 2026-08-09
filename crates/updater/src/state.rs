use serde::{Deserialize, Serialize};

use crate::error::{Result, UpdateError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Idle,
    CheckingForUpdates,
    NoUpdateAvailable,
    UpdateAvailable,
    PreparingDownload,
    Downloading,
    Paused,
    WaitingForNetwork,
    Resuming,
    Verifying,
    ReadyToInstall,
    WaitingForUserConfirmation,
    Installing,
    RestartRequired,
    Completed,
    Failed,
    Recovering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadQueueState {
    Queued,
    Downloading,
    Paused,
    WaitingForNetwork,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct UpdateStateMachine {
    state: UpdateState,
}

impl Default for UpdateStateMachine {
    fn default() -> Self {
        Self {
            state: UpdateState::Idle,
        }
    }
}

impl UpdateStateMachine {
    #[must_use]
    pub const fn state(&self) -> UpdateState {
        self.state
    }

    pub fn transition(&mut self, next: UpdateState) -> Result<()> {
        if self.can_transition(next) {
            self.state = next;
            Ok(())
        } else {
            Err(UpdateError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: format!("{next:?}"),
            })
        }
    }

    #[must_use]
    pub fn can_transition(&self, next: UpdateState) -> bool {
        use UpdateState as S;
        // A re-check is safe from any state that is not mid-transfer or
        // mid-install, so the user is never locked out of the Check action.
        let idle_for_check = matches!(
            self.state,
            S::Idle
                | S::NoUpdateAvailable
                | S::UpdateAvailable
                | S::ReadyToInstall
                | S::Completed
                | S::Failed
                | S::RestartRequired
        );
        if next == S::CheckingForUpdates {
            return idle_for_check;
        }
        // Cancelling returns to `UpdateAvailable`: the manifest is still valid,
        // only the transfer was abandoned.
        let cancellable = matches!(
            self.state,
            S::PreparingDownload
                | S::Downloading
                | S::Paused
                | S::WaitingForNetwork
                | S::Resuming
                | S::Verifying
                | S::ReadyToInstall
        );
        if next == S::UpdateAvailable && cancellable {
            return true;
        }
        matches!(
            (self.state, next),
            (
                S::CheckingForUpdates,
                S::NoUpdateAvailable | S::UpdateAvailable | S::Failed
            ) | (S::UpdateAvailable, S::PreparingDownload)
                | (
                    S::PreparingDownload | S::Resuming,
                    S::Downloading | S::Failed
                )
                | (
                    S::Downloading,
                    S::Paused | S::WaitingForNetwork | S::Verifying | S::Failed
                )
                | (
                    S::Paused | S::WaitingForNetwork,
                    S::Resuming | S::Downloading | S::Failed
                )
                | (S::Verifying, S::ReadyToInstall | S::Failed)
                | (S::ReadyToInstall, S::WaitingForUserConfirmation | S::Failed)
                | (
                    S::WaitingForUserConfirmation,
                    S::Installing | S::ReadyToInstall | S::Failed
                )
                | (
                    S::Installing,
                    S::RestartRequired | S::Completed | S::Recovering | S::Failed
                )
                | (
                    S::RestartRequired | S::Recovering,
                    S::Completed | S::Recovering | S::Failed
                )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{UpdateState, UpdateStateMachine};

    #[test]
    fn state_machine_accepts_happy_path() {
        let mut machine = UpdateStateMachine::default();
        for state in [
            UpdateState::CheckingForUpdates,
            UpdateState::UpdateAvailable,
            UpdateState::PreparingDownload,
            UpdateState::Downloading,
            UpdateState::Verifying,
            UpdateState::ReadyToInstall,
            UpdateState::WaitingForUserConfirmation,
            UpdateState::Installing,
            UpdateState::Completed,
        ] {
            machine.transition(state).unwrap();
        }
    }

    #[test]
    fn state_machine_rejects_install_without_confirmation() {
        let mut machine = UpdateStateMachine::default();
        assert!(machine.transition(UpdateState::Installing).is_err());
    }

    fn machine_at(states: &[UpdateState]) -> UpdateStateMachine {
        let mut machine = UpdateStateMachine::default();
        for state in states {
            machine.transition(*state).unwrap();
        }
        machine
    }

    #[test]
    fn cancelling_a_transfer_returns_to_update_available() {
        for tail in [
            UpdateState::Downloading,
            UpdateState::Paused,
            UpdateState::Verifying,
        ] {
            let mut machine = machine_at(&[
                UpdateState::CheckingForUpdates,
                UpdateState::UpdateAvailable,
                UpdateState::PreparingDownload,
                UpdateState::Downloading,
            ]);
            if tail != UpdateState::Downloading {
                machine.transition(tail).unwrap();
            }
            machine.transition(UpdateState::UpdateAvailable).unwrap();
            assert_eq!(machine.state(), UpdateState::UpdateAvailable);
        }
    }

    #[test]
    fn rechecking_is_allowed_from_every_settled_state() {
        for settled in [
            UpdateState::Idle,
            UpdateState::NoUpdateAvailable,
            UpdateState::UpdateAvailable,
            UpdateState::Completed,
            UpdateState::Failed,
            UpdateState::RestartRequired,
        ] {
            let mut machine = UpdateStateMachine { state: settled };
            assert!(
                machine.transition(UpdateState::CheckingForUpdates).is_ok(),
                "re-check must be allowed from {settled:?}",
            );
        }
    }

    #[test]
    fn rechecking_is_refused_while_a_transfer_or_install_is_running() {
        for busy in [
            UpdateState::CheckingForUpdates,
            UpdateState::PreparingDownload,
            UpdateState::Downloading,
            UpdateState::Paused,
            UpdateState::Installing,
        ] {
            let mut machine = UpdateStateMachine { state: busy };
            assert!(
                machine.transition(UpdateState::CheckingForUpdates).is_err(),
                "re-check must be refused while {busy:?}",
            );
        }
    }

    #[test]
    fn a_failed_install_can_be_retried_after_rechecking() {
        let mut machine = UpdateStateMachine {
            state: UpdateState::Installing,
        };
        machine.transition(UpdateState::Failed).unwrap();
        machine.transition(UpdateState::CheckingForUpdates).unwrap();
        assert_eq!(machine.state(), UpdateState::CheckingForUpdates);
    }
}
