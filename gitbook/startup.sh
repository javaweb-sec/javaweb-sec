GITBOOK_DIR=/data/javasec
cd $GITBOOK_DIR
gitbook install
gitbook build
nohup gitbook serve --port 8080 & >$GITBOOK_DIR/gitbook.log