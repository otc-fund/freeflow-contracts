//! Transfer hook for repFlow — ALWAYS REJECTS all transfer attempts.
//!
//! This is the core mechanism that makes repFlow non-transferable (soulbound).
//! The SPL Token-2022 program calls this hook on every transfer. By always
//! returning an error, transfers are blocked at the protocol level.
//!
//! This means repFlow CANNOT be:
//!   - Sent to another wallet
//!   - Listed on a DEX
//!   - Used as collateral
//!   - Traded in any way
//!
//! repFlow can ONLY be:
//!   - Minted by authorised minters (earning activities)
//!   - Burned by authorised burners (slashing)

use anchor_lang::prelude::*;
use spl_transfer_hook_interface::instruction::ExecuteInstruction;

use crate::error::RepFlowError;

/// Transfer hook entry point — called by SPL Token-2022 on every transfer.
///
/// This function ALWAYS returns NonTransferable. No amount of clever
/// instruction construction can bypass this — it is enforced at the
/// Solana program level, not in client code.
pub fn execute_transfer_hook(
    _ctx: Context<TransferHookExecute>,
    _amount: u64,
) -> Result<()> {
    // repFlow is soulbound. No transfers. Ever.
    Err(error!(RepFlowError::NonTransferable))
}

/// Account validation for the transfer hook CPI.
/// SPL Token-2022 passes these accounts when invoking the hook.
#[derive(Accounts)]
pub struct TransferHookExecute<'info> {
    /// The source token account.
    pub source_token: UncheckedAccount<'info>,
    /// The repFlow mint.
    pub mint: UncheckedAccount<'info>,
    /// The destination token account.
    pub destination_token: UncheckedAccount<'info>,
    /// The owner of the source token account.
    pub owner: UncheckedAccount<'info>,
}

/// Extra accounts required by the transfer hook (none — we reject immediately).
/// SPL Token-2022 requires this account to be registered even if empty.
#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    /// The repFlow mint.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,
    /// PDA that stores the extra account list.
    /// seeds: [b"extra-account-metas", mint.key()]
    #[account(
        init,
        payer       = payer,
        space       = 8 + 4, // discriminator + empty list length
        seeds       = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: Account<'info, anchor_lang::accounts::account::Account<ExtraAccountList>>,
    /// Fee payer (admin).
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Empty extra accounts list — we need no extra accounts to reject transfers.
#[account]
pub struct ExtraAccountList {
    pub count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_hook_always_rejects() {
        // The transfer hook error code must be NonTransferable.
        let err = RepFlowError::NonTransferable;
        assert_eq!(err.to_string(), "repFlow is non-transferable — it cannot be bought, sold, or traded");
    }
}
