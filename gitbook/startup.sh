GITBOOK_DIR=/data/wwwroot/javaweb-sec/gitbook/
cd $GITBOOK_DIR
npm install
npx honkit build
nohup npx honkit serve --port 23340 & >$GITBOOK_DIR/gitbook.log