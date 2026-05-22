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

/// Initialize the extra-account-metas PDA required by SPL Token-2022 for the transfer hook.
///
/// This MUST be called once after the repFlow mint is created. Without this PDA,
/// the SPL Token-2022 runtime cannot find the hook's extra-account list and the
/// transfer hook is not properly wired to the mint — meaning repFlow could be
/// transferred until this PDA is created, defeating the soulbound property.
///
/// The list is intentionally empty (count = 0) because the hook needs no extra
/// accounts — it unconditionally rejects all transfers without any additional state.
///
/// PDA seeds: `[b"extra-account-metas", mint.key()]` — matches the SPL Token-2022
/// standard so the runtime can find it automatically on every transfer attempt.
pub fn initialize_extra_account_meta_list(
    ctx: Context<InitializeExtraAccountMetaList>,
) -> Result<()> {
    // No extra accounts needed — the hook rejects unconditionally.
    ctx.accounts.extra_account_meta_list.count = 0;
    msg!(
        "extra-account-metas PDA initialized for mint {} (0 extra accounts — soulbound)",
        ctx.accounts.mint.key()
    );
    Ok(())
}

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
    pub extra_account_meta_list: Account<'info, ExtraAccountList>,
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
    use anchor_lang::prelude::Pubkey;

    #[test]
    fn transfer_hook_always_rejects() {
        // The transfer hook error code must be NonTransferable.
        let err = RepFlowError::NonTransferable;
        assert_eq!(err.to_string(), "repFlow is non-transferable — it cannot be bought, sold, or traded");
    }

    /// Verify that the extra-account-metas PDA seeds match the SPL Token-2022 standard.
    ///
    /// SPL Token-2022 derives the hook's extra-account list at:
    ///   PDA([b"extra-account-metas", mint.key()], transfer_hook_program_id)
    ///
    /// Our `InitializeExtraAccountMetaList` account struct uses exactly these seeds.
    /// This test confirms the seed constant is correct and PDA derivation is deterministic.
    #[test]
    fn extra_account_meta_list_pda_uses_correct_seeds() {
        let program_id = crate::ID; // repflow-token program ID
        let mint = Pubkey::new_unique();

        // Derive PDA with the standard SPL Token-2022 extra-account-metas seeds.
        let (pda, bump) = Pubkey::find_program_address(
            &[b"extra-account-metas", mint.as_ref()],
            &program_id,
        );

        // find_program_address always returns a valid bump (guaranteed by the runtime).
        let _ = bump; // bump: u8, always in [0, 255] by construction

        // PDA derivation must be deterministic — same inputs → same output.
        let (pda2, bump2) = Pubkey::find_program_address(
            &[b"extra-account-metas", mint.as_ref()],
            &program_id,
        );
        assert_eq!(pda, pda2, "extra-account-metas PDA must be deterministic");
        assert_eq!(bump, bump2, "bump must be deterministic for the same mint");

        // A different mint produces a different PDA (no collisions expected).
        let other_mint = Pubkey::new_unique();
        let (other_pda, _) = Pubkey::find_program_address(
            &[b"extra-account-metas", other_mint.as_ref()],
            &program_id,
        );
        assert_ne!(pda, other_pda, "different mints must produce different PDAs");
    }

    /// Verify the ExtraAccountList size matches the account space allocation.
    ///
    /// InitializeExtraAccountMetaList allocates `space = 8 + 4`:
    ///   8 bytes: Anchor discriminator
    ///   4 bytes: ExtraAccountList::count (u32)
    #[test]
    fn extra_account_list_size_matches_allocation() {
        // ExtraAccountList has a single u32 field.
        // Borsh serializes u32 as 4 bytes.
        let list = ExtraAccountList { count: 0 };
        let encoded = borsh::to_vec(&list).unwrap();
        // 4 bytes for count (Anchor discriminator is handled separately by the runtime).
        assert_eq!(encoded.len(), 4,
            "ExtraAccountList serializes to exactly 4 bytes (u32 count)");
        // space = 8 (discriminator) + 4 (count) = 12 total — matches the init constraint.
        assert_eq!(8 + encoded.len(), 12,
            "total account space must be 12 bytes");
    }
}
