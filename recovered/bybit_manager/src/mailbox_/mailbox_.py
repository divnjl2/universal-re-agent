"""
RECOVERED: mailbox_.mailbox_
Skeleton reconstructed from Nuitka binary metadata.
"""

from . import *  # from mailbox_

# === Constants ===
CASE_INSENSITIVE_MAILBOX_NAMES = None  # RECOVERED
MAILBOX_PROXY_ERRORS = None  # RECOVERED
SMTP_UTF8_MAILBOX = None  # RECOVERED

class BaseMailBox(object):
    """RECOVERED: BaseMailBox from mailbox_.mailbox_"""
    pass

class MailBox(object):
    """RECOVERED: MailBox from mailbox_.mailbox_"""
    async def _get_mailbox_client(self):  # RECOVERED
        raise NotImplementedError

    async def get_mailbox_service(self):  # RECOVERED
        raise NotImplementedError

    async def imap_createmailbox(self):  # RECOVERED
        raise NotImplementedError

    async def imap_deletemailbox(self):  # RECOVERED
        raise NotImplementedError

    async def imap_getmailboxes(self):  # RECOVERED
        raise NotImplementedError

    async def imap_listmailbox(self):  # RECOVERED
        raise NotImplementedError

    async def imap_mailboxmsginfo(self):  # RECOVERED
        raise NotImplementedError

    async def imap_renamemailbox(self):  # RECOVERED
        raise NotImplementedError


class MailBoxFolderManager(object):
    """RECOVERED: MailBoxFolderManager from mailbox_.mailbox_"""
    pass

class MailBoxFolderStatusOptions(object):
    """RECOVERED: MailBoxFolderStatusOptions from mailbox_.mailbox_"""
    pass

class MailBoxStartTls(object):
    """RECOVERED: MailBoxStartTls from mailbox_.mailbox_"""
    pass

class MailBoxUnencrypted(object):
    """RECOVERED: MailBoxUnencrypted from mailbox_.mailbox_"""
    pass

class MailboxAppendError(Exception):
    """RECOVERED: MailboxAppendError from mailbox_.mailbox_"""
    pass

class MailboxCopyError(Exception):
    """RECOVERED: MailboxCopyError from mailbox_.mailbox_"""
    pass

class MailboxDeleteError(Exception):
    """RECOVERED: MailboxDeleteError from mailbox_.mailbox_"""
    pass

class MailboxExpungeError(Exception):
    """RECOVERED: MailboxExpungeError from mailbox_.mailbox_"""
    pass
