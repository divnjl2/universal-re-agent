"""
RECOVERED: imap_tools.mailbox
Skeleton reconstructed from Nuitka binary metadata.
"""

from . import *  # from imap_tools

# === Constants ===
CASE_INSENSITIVE_MAILBOX_NAMES = None  # RECOVERED
EMAIL_IMAP_ADDRESS_COLUMN = None  # RECOVERED
EMAIL_IMAP_PASSWORD_COLUMN = None  # RECOVERED
IMAP4_SSL = None  # RECOVERED
IMAP_PASSWORD_REQUIRED = None  # RECOVERED
INPLACE_E_NOTOOLSPACE = None  # RECOVERED
MAILBOX_PROXY_ERRORS = None  # RECOVERED
SMTP_UTF8_MAILBOX = None  # RECOVERED

class BaseMailBox(object):
    """RECOVERED: BaseMailBox from imap_tools.mailbox"""
    pass

class HttpToolsProtocol(object):
    """RECOVERED: HttpToolsProtocol from imap_tools.mailbox"""
    pass

class ImapToolsError(Exception):
    """RECOVERED: ImapToolsError from imap_tools.mailbox"""
    pass

class MailBox(object):
    """RECOVERED: MailBox from imap_tools.mailbox"""
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
    """RECOVERED: MailBoxFolderManager from imap_tools.mailbox"""
    pass

class MailBoxFolderStatusOptions(object):
    """RECOVERED: MailBoxFolderStatusOptions from imap_tools.mailbox"""
    pass

class MailBoxStartTls(object):
    """RECOVERED: MailBoxStartTls from imap_tools.mailbox"""
    pass

class MailBoxUnencrypted(object):
    """RECOVERED: MailBoxUnencrypted from imap_tools.mailbox"""
    pass

class MailboxAppendError(Exception):
    """RECOVERED: MailboxAppendError from imap_tools.mailbox"""
    pass

class MailboxCopyError(Exception):
    """RECOVERED: MailboxCopyError from imap_tools.mailbox"""
    pass
