<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\RefreshToken;
use Carbon\Carbon;

class DeleteExpiredRefreshTokens extends Command
{
    protected $signature = 'refresh-tokens:cleanup';
    protected $description = 'Deletes expired refresh tokens from the database';

    public function __construct()
    {
        parent::__construct();
    }

    public function handle()
    {
        $deleted = RefreshToken::where('expires_at', '<', Carbon::now())->delete();
        $this->info("Deleted {$deleted} expired refresh tokens.");
    }
}
