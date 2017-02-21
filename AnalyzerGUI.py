import tkMessageBox
from Tkinter import *
from ttk import *
from tkFileDialog import askopenfilename
import matplotlib, numpy
import matplotlib.ticker as ticker
from pylab import plt
import networkx as nx
import matplotlib.patches as mpatches

matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure

from DB import *
from ReadPCAP import *

# Global var
db = 0


class Gui(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)

        # init root window
        self.parent = parent
        self.parent.title("Network Traffic Analyzer 1.0.0")
        self.pack(fill=BOTH, expand=1)
        self.centerWindow()

        # init menu bar
        self.initMenu()

    def on_closing(self):

        root.destroy()

    def centerWindow(self):
        w = 1000
        h = 600

        sw = self.parent.winfo_screenwidth()
        sh = self.parent.winfo_screenheight()

        x = (sw - w) / 2
        y = (sh - h) / 2
        # self.parent.geometry('%dx%d+%d+%d' % (w, h, x, y))
        self.parent.geometry('%dx%d' % (sw, sh))

    def initMenu(self):
        menu = Menu(root)
        root.config(menu=menu)
        filemenu = Menu(menu)
        menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="Open PCAP File", command=self.openFile)
        filemenu.add_command(label="Load DB", command=self.loadFile)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=root.quit)

        helpmenu = Menu(menu)
        menu.add_cascade(label="Help", menu=helpmenu)
        helpmenu.add_command(label="About", command=self.about)

    def initTabs(self):
        note = Notebook(root)

        self.tabConnections = Frame(note)
        self.tabPktInCnl = Frame(note)
        self.tabPERByUsr = Frame(note)
        self.tabUsrOnCnl = Frame(note)
        self.tabCnlPER = Frame(note)
        self.tabSSID = Frame(note)
        self.tabRouters = Frame(note)
        self.tabTalks = Frame(note)

        # add tab and bind to its corresponding graph
        note.add(self.tabPktInCnl, text="Packets In Channel")
        self.tabPktInCnl.bind("<Button-1>", self.showPacketsInChannelGraph())

        note.add(self.tabPERByUsr, text="PER By User")
        self.tabPERByUsr.bind("<Button-1>", self.showPerByUserGraph())

        note.add(self.tabCnlPER, text="PER By Channel")
        self.tabCnlPER.bind("<Button-1>", self.showPerByChannelGraph())

        note.add(self.tabUsrOnCnl, text="Users On Channel")
        self.tabUsrOnCnl.bind("<Button-1>", self.showUsersOnChannelGraph())

        note.add(self.tabSSID, text="Users On Network")
        self.tabSSID.bind("<Button-1>", self.showSSIDGraph())

        note.add(self.tabRouters, text="Routers Map")
        self.tabRouters.bind("<Button-1>", self.showRoutersGraph())

        note.add(self.tabTalks, text="Talk To")
        self.tabTalks.bind("<Button-1>", self.selectSession())

        note.place(x=0, y=5)

    def initFrame(self):
        frame = Frame()

    def loadFile(self):
        try:
            fileName = askopenfilename()
            dbName = fileName[fileName.rindex("/") + 1:fileName.rindex(".")]
            global db
            db = DB(dbName)
            print "loaded file"
            self.initTabs()
        except:
            pass

    def openFile(self):
        labelfont = ('times', 20, 'bold')
        loadingMsg = Label(self.parent, text="Loading...")
        loadingMsg.place(x=500, y=300)
        loadingMsg.config(font=labelfont)
        try:
            fileName = askopenfilename()
            start = time.time()
            # set DB name and create it
            dbName = fileName[fileName.rindex("/") + 1:fileName.rindex(".")]
            global db
            db = DB(dbName)
            db.createDB()
            # init and start parse
            parser = Parser(fileName)
            parser.startParse()

            # insert to DB
            db.insertToTable("usage", parser.getUsageData())
            db.insertToTable("routers", parser.getRouterData())
            db.insertToTable("session", parser.getSessionData())
            db.insertToTable("routers_client", parser.getRouterClientData())

            end = time.time()
            loadingMsg.destroy()
            print 'Parsing took %0.3f sec' % (end - start)
            tkMessageBox.showinfo("Database created",
                                  "Done loading data.")
            self.initTabs()
        except:
            print "Error creating DB"
            pass

    def about(self):
        tkMessageBox.showinfo("About", "This is Network Analyzer used to get data about network and network quality.\n"
                                       "Version - 1.0.0")

    def showPerByUserGraph(self):
        f = Figure(figsize=(13, 6.5), dpi=100)
        ax = f.add_subplot(111)

        # Get data from database
        global db
        users = db.getUserUsage()

        macs = []
        sent = []
        retransmit = []

        for usr in users:
            macs.append(usr[0])
            sent.append(usr[1])
            retransmit.append(usr[2])

        index = numpy.arange(len(users))  # the x locations for the groups
        bar_width = .1
        opacity = 0.4

        avg = numpy.average(sent)

        rects1 = ax.bar(index + 0.25, sent, bar_width,
                        alpha=opacity,
                        color='b',
                        label='Sent')

        rects2 = ax.bar(index + 0.25 + bar_width, retransmit, bar_width,
                        alpha=opacity,
                        color='r',
                        label='Retransmit')

        ax.legend(loc=1)

        title = "PACKETS PER By USER"
        ax.set_title(title)
        ax.set_ylabel('Packets')
        ax.set_xticks(index)
        ax.set_xticklabels(macs, fontsize='small', ha='right', rotation=20)
        ax.set_xlim([0, 9])
        ax.set_ylim([0, avg])

        for i, v in enumerate(sent):
            ax.text(i, v + 5, str(v) + " | " + str(retransmit[i]), color='black')

        # for i, v in enumerate(retransmit):
        #     ax.text(i, v+100, str(v), color='black')

        canvas = FigureCanvasTkAgg(f, master=self.tabPERByUsr)

        toolbar = NavigationToolbar2TkAgg(canvas, self.tabPERByUsr)
        toolbar.update()
        canvas._tkcanvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.show()

    def showPerByChannelGraph(self):
        f = Figure(figsize=(13, 6.5), dpi=100)
        ax = f.add_subplot(111)

        # Get data from database
        global db
        channels = db.getPERByChannel()

        channel = []
        sent = []
        retransmit = []

        for cnl in channels:
            channel.append(cnl[0])
            sent.append(cnl[1])
            retransmit.append(cnl[2])

        index = numpy.arange(len(channel))  # the x locations for the groups
        bar_width = 0.2
        opacity = 0.4

        avg = numpy.average(retransmit)
        avgRate = avg / numpy.sum(retransmit) * 100.0

        rects1 = ax.bar(index, retransmit, bar_width,
                        alpha=opacity,
                        color='r',
                        label='Retransmit')

        ax.legend(loc=1)

        title = "PER by channel - " + str(avgRate) + " %"
        ax.set_title(title)
        ax.set_ylabel('Packets')
        ax.set_xlabel('Channel')
        ax.set_xticks(index)
        ax.set_xticklabels(channel, fontsize='small', ha='center')

        ax.yaxis.set_major_locator(ticker.MultipleLocator(avg))

        for i, v in enumerate(retransmit):
            ax.text(i, v + 100, str(v), color='black')

        canvas = FigureCanvasTkAgg(f, master=self.tabCnlPER)

        toolbar = NavigationToolbar2TkAgg(canvas, self.tabCnlPER)
        toolbar.update()
        canvas._tkcanvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.show()

    def showUsersOnChannelGraph(self):
        f = Figure(figsize=(13, 6.5), dpi=100)
        ax = f.add_subplot(111)

        # Get data from database
        global db
        connections = db.getUsersOnChannel()

        channel = []
        users = []

        for con in connections:
            channel.append(con[0])
            users.append(con[1])

        index = numpy.arange(len(channel))  # the x locations for the groups
        bar_width = 0.2
        opacity = 0.4

        avg = numpy.average(users)
        # avgRate = avg / numpy.sum(retransmit) * 100.0

        rects1 = ax.bar(index, users, bar_width,
                        alpha=opacity,
                        color='g',
                        label='Users')

        ax.legend(loc=1)

        title = "Users on channel"
        ax.set_title(title)
        ax.set_ylabel('Users')
        ax.set_xlabel('Channel')
        ax.set_xticks(index)
        ax.set_xticklabels(channel, fontsize='small', ha='center')

        ax.yaxis.set_major_locator(ticker.MultipleLocator(avg))

        for i, v in enumerate(users):
            ax.text(i, v, str(v), color='black')

        canvas = FigureCanvasTkAgg(f, master=self.tabUsrOnCnl)

        toolbar = NavigationToolbar2TkAgg(canvas, self.tabUsrOnCnl)
        toolbar.update()
        canvas._tkcanvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.show()

    def showPacketsInChannelGraph(self):
        f = Figure(figsize=(13, 6.5), dpi=100)
        ax = f.add_subplot(111)

        # Get data from database
        global db
        channels = db.getPacketsByChannel()

        channel = []
        pkts = []

        for cnl in channels:
            channel.append(cnl[0])
            pkts.append(cnl[1])

        index = numpy.arange(len(channel))  # the x locations for the groups
        bar_width = 0.2
        opacity = 0.4

        avg = numpy.average(pkts)

        rects1 = ax.bar(index, pkts, bar_width,
                        alpha=opacity,
                        color='g',
                        label='Packets')

        ax.legend(loc=1)

        title = "Packet in channel"
        ax.set_title(title)
        ax.set_ylabel('Packets')
        ax.set_xlabel('Channel')
        ax.set_xticks(index)
        ax.set_xticklabels(channel, fontsize='small', ha='center')

        ax.yaxis.set_major_locator(ticker.MultipleLocator(avg))

        for i, v in enumerate(pkts):
            ax.text(i, v, str(v), color='black')

        canvas = FigureCanvasTkAgg(f, master=self.tabPktInCnl)

        toolbar = NavigationToolbar2TkAgg(canvas, self.tabPktInCnl)
        toolbar.update()
        canvas._tkcanvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.show()

    def showSSIDGraph(self):
        f = Figure(figsize=(13, 6.5), dpi=100)
        ax = f.add_subplot(111)

        # Get data from database
        global db
        ssids = db.getRouters()

        ssid = []
        connections = []

        for id in ssids:
            ssid.append(id[0])
            connections.append(id[1])

        index = numpy.arange(len(ssid))  # the x locations for the groups
        bar_width = 0.2
        opacity = 0.4

        avg = numpy.average(connections)

        rects1 = ax.bar(index, connections, bar_width,
                        alpha=opacity,
                        color='b',
                        label='Users')

        ax.legend(loc=1)

        title = "Connection By SSID "
        ax.set_title(title)
        ax.set_ylabel('Connections')
        ax.set_xticks(index)
        ax.set_xticklabels(ssid, fontsize='small', ha='center', rotation=10)

        ax.yaxis.set_major_locator(ticker.MultipleLocator(avg))

        for i, v in enumerate(connections):
            ax.text(i, v, str(v), color='black')

        canvas = FigureCanvasTkAgg(f, master=self.tabSSID)

        toolbar = NavigationToolbar2TkAgg(canvas, self.tabSSID)
        toolbar.update()
        canvas._tkcanvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.show()

    def showRoutersGraph(self):

        # build the frame
        f = plt.figure(figsize=(5, 4))
        a = f.add_subplot(111)
        # plt.axis('off')

        # Get data from database
        global db
        sessions = db.getClientsFromRouters()

        # the networkx part
        G = nx.Graph()
        a.cla()
        routers = []
        clients = []
        edgeList = []

        # (ROUTER, CLIENT)
        for ssn in sessions:
            routers.append(ssn[0])
            clients.append(ssn[1])
            edgeList.append((ssn[0], ssn[1]))
            # G.add_edges_from([(ssn[0], ssn[1])], weight=1)

        G.add_nodes_from(routers)
        G.add_nodes_from(clients)
        G.add_edges_from(edgeList, weight=1)

        edge_labels = dict([((u, v,), d['weight'])
                            for u, v, d in G.edges(data=True)])

        pos = nx.circular_layout(G)

        # a tk.DrawingArea
        canvas = FigureCanvasTkAgg(f, master=self.tabRouters)
        # canvas.get_tk_widget().pack(side=Tk.TOP, fill=Tk.BOTH, expand=1)

        nx.draw_networkx_nodes(G, pos, ax=a,
                               nodelist=routers,
                               node_color='r',
                               node_size=1000,
                               alpha=0.8)

        nx.draw_networkx_nodes(G, pos, ax=a,
                               nodelist=clients,
                               node_color='b',
                               node_size=1000,
                               alpha=0.8)

        nx.draw_networkx_edges(G, pos, ax=a,
                               edgelist=edgeList,
                               width=8, alpha=0.5, edge_color='b')

        node_labels = {node: node for node in G.nodes()}

        nx.draw_networkx_edges(G, pos, ax=a,
                               edgelist=edgeList,
                               width=8, alpha=0.5, edge_color='b')

        nx.draw_networkx_labels(G, pos, labels=node_labels)

        plt.axis('off')
        AP = mpatches.Patch(color='red', label='Router')
        CL = mpatches.Patch(color='blue', label='Client')

        plt.legend(handles=[AP, CL], loc=1)

        canvas = FigureCanvasTkAgg(f, master=self.tabRouters)

        toolbar = NavigationToolbar2TkAgg(canvas, self.tabRouters)
        toolbar.update()
        canvas._tkcanvas.pack(side=RIGHT, fill=BOTH, expand=True)
        canvas.show()

    def selectSession(self):
        userLabel = Label(self.tabTalks, text="Users:", font=("Helvetica", 14))
        userLabel.place(x=0, y=0)
        self.userList = Listbox(self.tabTalks, width=20, height=44)
        self.userList.pack(side=LEFT, fill=BOTH, expand=1)
        self.userList.place(x=0, y=20)
        self.scrollbar = Scrollbar(self.tabTalks, orient=VERTICAL, command=self.userList.yview)
        self.scrollbar.place(x=149, y=20, height=662)
        self.userList.config(yscrollcommand=self.scrollbar.set)

        user2Label = Label(self.tabTalks, text="Talk to:", font=("Helvetica", 14))
        user2Label.place(x=300, y=0)
        self.userList2 = Listbox(self.tabTalks, width=20, height=44)
        self.userList2.pack(side=RIGHT, fill=BOTH, expand=1)
        self.userList2.place(x=300, y=20)
        self.scrollbar2 = Scrollbar(self.tabTalks, orient=VERTICAL, command=self.userList2.yview)
        self.scrollbar2.place(x=449, y=21, height=662)
        self.userList2.config(yscrollcommand=self.scrollbar2.set)

        global db
        users = db.getUsers()

        for user in users:
            self.userList.insert(END, user)

        self.userList.bind('<ButtonRelease-1>', self.showSessions)

    def showSessions(self, event):
        """
        function to read the listbox selection
        and put the result in an entry widget
        """
        # clear the former text
        self.userList2.delete(0, END)
        # get selected line index
        index = self.userList.curselection()[0]
        # get the line's text
        user = self.userList.get(index)
        global db
        userSession = db.getUserSession(user)
        for user in userSession:
            self.userList2.insert(END, user)

root = Tk()
ex = Gui(root)

root.mainloop()
