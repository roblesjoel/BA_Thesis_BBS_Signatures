module VC.BBS {
    opens ch.bfh.vcbbs.types to com.fasterxml.jackson.databind;
    requires ch.bfh.p2bbs.bbs;
    requires ch.openchvote.utilities;
    requires com.fasterxml.jackson.databind;
}