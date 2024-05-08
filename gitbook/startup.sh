GITBOOK_DIR=/data/javasec
cd $GITBOOK_DIR
gitbook install
gitbook build
nohup gitbook serve --port 23340 --no-live & >$GITBOOK_DIR/gitbook.log