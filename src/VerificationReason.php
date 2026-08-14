<?php

declare(strict_types=1);

namespace Infocyph\OTP;

enum VerificationReason: string
{
    case Drifted = 'drifted';

    case Malformed = 'malformed';

    case Matched = 'matched';

    case Mismatch = 'mismatch';

    case Replay = 'replay';

    case Resynchronized = 'resynchronized';
}
